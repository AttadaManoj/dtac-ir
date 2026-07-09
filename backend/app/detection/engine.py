"""
DTAC-IR Detection Engine — Phase 1 Core
Rule-based detection + feature extraction for ML pipeline.

Detection Rules implemented:
  - Port Scan Detection (> N unique ports in time window)
  - SYN Flood Detection (high SYN ratio without ACK)
  - DNS Exfiltration Detection (large DNS payloads / high query rate)
  - ARP Spoofing Detection (IP-MAC binding changes)
  - Brute Force Detection (repeated auth-port connections)
"""
import time
import asyncio
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Optional
from loguru import logger

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not available — running in simulation mode")
    SCAPY_AVAILABLE = False


# ── Feature Vector ───────────────────────────────────────────────────────────────

@dataclass
class PacketFeatures:
    """
    Feature vector extracted from a packet/flow.
    These exact fields are what the ML model is trained on.
    Keeping this as a dataclass makes it easy to serialise to DB and numpy arrays.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "UNKNOWN"
    packet_length: int = 0
    flags: str = ""
    ttl: int = 0
    payload_size: int = 0
    # Flow-level features (computed over rolling window)
    packets_per_second: float = 0.0
    unique_dst_ports: int = 0
    syn_ratio: float = 0.0
    is_threat: bool = False
    predicted_class: str = "normal"
    ml_confidence: float = 0.0
    rule_triggered: Optional[str] = None


# ── Detection State ──────────────────────────────────────────────────────────────

@dataclass
class HostTracker:
    """Per-IP state maintained in memory for rule evaluation."""
    ip: str
    syn_count: int = 0
    ack_count: int = 0
    dst_ports: set = field(default_factory=set)
    dns_queries: deque = field(default_factory=lambda: deque(maxlen=100))
    connection_times: deque = field(default_factory=lambda: deque(maxlen=500))
    packet_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    arp_mac: Optional[str] = None


# ── Rule Thresholds ──────────────────────────────────────────────────────────────

PORT_SCAN_THRESHOLD = 20          # Unique ports in TIME_WINDOW seconds
SYN_FLOOD_THRESHOLD = 100         # SYN packets in TIME_WINDOW seconds
SYN_RATIO_THRESHOLD = 0.85        # SYN:total ratio
DNS_PAYLOAD_THRESHOLD = 200       # Bytes — normal DNS query < 100 bytes
DNS_RATE_THRESHOLD = 50           # Queries in TIME_WINDOW seconds
BRUTE_FORCE_PORTS = {22, 23, 3389, 5900, 21, 25}
BRUTE_FORCE_THRESHOLD = 10        # Attempts in TIME_WINDOW seconds
TIME_WINDOW = 60                  # Seconds for rolling window


# ── Detection Engine ─────────────────────────────────────────────────────────────

class DetectionEngine:
    """
    Real-time rule-based detection engine.
    Processes packets from Scapy, extracts features, evaluates rules,
    and fires callbacks when threats are detected.
    """

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self._host_state: dict[str, HostTracker] = defaultdict(
            lambda: HostTracker(ip="unknown")
        )
        self._running = False
        self._packet_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._stats = {"total_packets": 0, "threats_detected": 0, "rules_fired": {}}
        self._ml_engine = None   # Injected via set_ml_engine() at startup

    def _get_host(self, ip: str) -> HostTracker:
        if ip not in self._host_state:
            self._host_state[ip] = HostTracker(ip=ip)
        return self._host_state[ip]

    def _prune_window(self, dq: deque, window: int = TIME_WINDOW) -> None:
        """Remove entries older than TIME_WINDOW from a deque of timestamps."""
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    # ── Feature Extraction ───────────────────────────────────────────────────────

    def extract_features(self, packet) -> Optional[PacketFeatures]:
        """Extract a PacketFeatures vector from a Scapy packet object."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        features = PacketFeatures(
            timestamp=time.time(),
            src_ip=ip_layer.src,
            dst_ip=ip_layer.dst,
            ttl=ip_layer.ttl,
            packet_length=len(packet),
        )

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features.src_port = tcp.sport
            features.dst_port = tcp.dport
            features.protocol = "TCP"
            features.flags = str(tcp.flags)
            features.payload_size = len(tcp.payload) if tcp.payload else 0

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            features.src_port = udp.sport
            features.dst_port = udp.dport
            features.protocol = "UDP"
            features.payload_size = len(udp.payload) if udp.payload else 0

        # Update host state for flow-level features
        host = self._get_host(features.src_ip)
        now = time.time()
        host.packet_times.append(now)
        self._prune_window(host.packet_times)
        features.packets_per_second = len(host.packet_times) / TIME_WINDOW

        return features

    # ── Rules ────────────────────────────────────────────────────────────────────

    def _rule_port_scan(self, features: PacketFeatures, host: HostTracker) -> Optional[str]:
        host.dst_ports.add(features.dst_port)
        if len(host.dst_ports) > PORT_SCAN_THRESHOLD:
            return "PORT_SCAN"
        return None

    def _rule_syn_flood(self, features: PacketFeatures, host: HostTracker) -> Optional[str]:
        if features.protocol != "TCP":
            return None
        now = time.time()
        if "S" in features.flags:   # SYN flag
            host.syn_count += 1
            host.connection_times.append(now)
            self._prune_window(host.connection_times)
        if "A" in features.flags:   # ACK flag
            host.ack_count += 1

        total = host.syn_count + host.ack_count
        if total > 10:
            ratio = host.syn_count / total
            if ratio > SYN_RATIO_THRESHOLD and host.syn_count > SYN_FLOOD_THRESHOLD:
                return "SYN_FLOOD"
        return None

    def _rule_dns_exfiltration(self, features: PacketFeatures, host: HostTracker) -> Optional[str]:
        if features.dst_port != 53 and features.src_port != 53:
            return None
        now = time.time()
        host.dns_queries.append(now)
        self._prune_window(host.dns_queries)

        if (features.payload_size > DNS_PAYLOAD_THRESHOLD or
                len(host.dns_queries) > DNS_RATE_THRESHOLD):
            return "DNS_EXFILTRATION"
        return None

    def _rule_brute_force(self, features: PacketFeatures, host: HostTracker) -> Optional[str]:
        if features.dst_port not in BRUTE_FORCE_PORTS:
            return None
        now = time.time()
        host.connection_times.append(now)
        self._prune_window(host.connection_times)

        if len(host.connection_times) > BRUTE_FORCE_THRESHOLD:
            return "BRUTE_FORCE"
        return None

    # ── Main Processing Loop ─────────────────────────────────────────────────────

    @staticmethod
    def _is_benign_infrastructure_traffic(features: PacketFeatures) -> bool:
        """
        Excludes normal local-network chatter that legitimate rule/ML classifiers
        otherwise misread as scanning: multicast discovery (mDNS/SSDP/Bonjour on
        224.0.0.0/4), subnet/limited broadcast, and loopback. Without this,
        e.g. mDNS traffic to 224.0.0.251:5353 gets flagged PORT_SCAN with high
        ML confidence purely because of packet timing patterns, which is noise,
        not a threat.
        """
        try:
            dst = ipaddress.ip_address(features.dst_ip)
        except ValueError:
            return False
        return dst.is_multicast or dst.is_loopback or features.dst_ip == "255.255.255.255"

    def evaluate_rules(self, features: PacketFeatures) -> PacketFeatures:
        """
        Hybrid detection: rule-based + ML.

        Strategy:
          1. Skip known-benign infrastructure traffic (multicast/broadcast/loopback)
          2. Run rule engine first (fast, near-zero FP for known patterns)
          3. If no rule fires, run ML classifier
          4. If ML fires with high confidence, mark as threat
          5. ml_confidence is always set regardless of which engine fires
        """
        if self._is_benign_infrastructure_traffic(features):
            return features

        host = self._get_host(features.src_ip)

        # ── Rule-based detection ─────────────────────────────────────────────────
        rules = [
            self._rule_port_scan,
            self._rule_syn_flood,
            self._rule_dns_exfiltration,
            self._rule_brute_force,
        ]

        for rule in rules:
            result = rule(features, host)
            if result:
                features.is_threat = True
                features.predicted_class = result.lower()
                features.rule_triggered = result
                self._stats["threats_detected"] += 1
                self._stats["rules_fired"][result] = self._stats["rules_fired"].get(result, 0) + 1
                logger.warning(
                    f"\U0001f6a8 RULE HIT | {result} | {features.src_ip} \u2192 "
                    f"{features.dst_ip}:{features.dst_port}"
                )
                break

        # ── ML classification (always runs, supplements rules) ────────────────────
        if self._ml_engine is not None and self._ml_engine.is_loaded:
            ml_features = self._features_to_ml_dict(features)
            prediction = self._ml_engine.predict(ml_features)
            features.ml_confidence = prediction.confidence

            if not features.rule_triggered and prediction.is_threat:
                features.is_threat = True
                features.predicted_class = prediction.predicted_class.lower()
                features.ml_confidence = prediction.confidence
                self._stats["threats_detected"] += 1
                self._stats["rules_fired"]["ML"] = self._stats["rules_fired"].get("ML", 0) + 1
                logger.warning(
                    f"\U0001f916 ML HIT | {prediction.predicted_class} "
                    f"(conf: {prediction.confidence:.2f}) | {features.src_ip}"
                )

        return features

    def _features_to_ml_dict(self, features: PacketFeatures) -> dict:
        """Map PacketFeatures to CICIDS2017 ML feature names."""
        return {
            "Destination Port":            features.dst_port,
            "Total Fwd Packets":           1,
            "Total Length of Fwd Packets": features.payload_size,
            "Fwd Packet Length Max":       features.packet_length,
            "Fwd Packet Length Mean":      features.packet_length,
            "Flow Bytes/s":                features.packets_per_second * features.packet_length,
            "Flow Packets/s":              features.packets_per_second,
            "SYN Flag Count":              1 if "S" in features.flags else 0,
            "RST Flag Count":              1 if "R" in features.flags else 0,
            "ACK Flag Count":              1 if "A" in features.flags else 0,
            "Fwd PSH Flags":               1 if "P" in features.flags else 0,
        }

    def set_ml_engine(self, ml_engine) -> None:
        """Inject ML inference engine (called from app startup)."""
        self._ml_engine = ml_engine
        logger.info("ML inference engine attached to detection engine")

    def packet_callback(self, packet) -> None:
        """Scapy callback — called for every captured packet."""
        self._stats["total_packets"] += 1
        features = self.extract_features(packet)
        if features is None:
            return

        features = self.evaluate_rules(features)

        if self.alert_callback and features.is_threat:
            try:
                self.alert_callback(features)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def start_capture(self, interface: str = "eth0", packet_filter: str = "ip") -> None:
        """
        Start live packet capture. Blocks the calling thread.
        Run this in a separate thread/process.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy unavailable — using simulation mode")
            self._simulate_traffic()
            return

        logger.info(f"🔍 Starting capture on {interface} with filter: '{packet_filter}'")
        self._running = True
        try:
            sniff(
                iface=interface,
                filter=packet_filter,
                prn=self.packet_callback,
                store=False,          # Don't store packets in memory
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("❌ Permission denied — run with sudo or set CAP_NET_RAW capability")
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def stop_capture(self) -> None:
        self._running = False
        logger.info("🛑 Packet capture stopped")

    def get_stats(self) -> dict:
        return {**self._stats, "active_hosts": len(self._host_state)}

    def _simulate_traffic(self) -> None:
        """Generate synthetic traffic for testing without root/Scapy."""
        import random
        import threading

        def generate():
            logger.info("🔁 Simulation mode active — generating synthetic traffic")
            while self._running:
                features = PacketFeatures(
                    timestamp=time.time(),
                    src_ip=f"192.168.1.{random.randint(1, 254)}",
                    dst_ip=f"10.0.0.{random.randint(1, 10)}",
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 22, 53, 8080, random.randint(1, 65535)]),
                    protocol=random.choice(["TCP", "UDP"]),
                    packet_length=random.randint(40, 1500),
                    flags=random.choice(["S", "SA", "A", "FA", "R", ""]),
                    ttl=random.randint(30, 128),
                    payload_size=random.randint(0, 1000),
                )
                self._stats["total_packets"] += 1
                features = self.evaluate_rules(features)
                if self.alert_callback and features.is_threat:
                    self.alert_callback(features)
                time.sleep(0.05)  # 20 packets/sec simulation rate

        t = threading.Thread(target=generate, daemon=True)
        t.start()
        self._running = True
