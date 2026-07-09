"""
DTAC-IR Trust Scoring Engine
The "T" in DTAC — Dynamic Trust Assessment & Control.

Trust score (0–100) per device based on:
  - Alert history (severity-weighted deductions)
  - Temporal decay (score recovers over time without incidents)
  - ML confidence (high-confidence detections penalise more)
  - Baseline behaviour deviation
"""
import time
import math
from dataclasses import dataclass
from typing import Optional
from loguru import logger

from app.core.config import get_settings

settings = get_settings()


# ── Score Modifiers ──────────────────────────────────────────────────────────────

SEVERITY_DEDUCTIONS = {
    "critical": 30.0,
    "high":     15.0,
    "medium":    7.0,
    "low":       2.0,
}

ATTACK_MULTIPLIERS = {
    "syn_flood":        1.5,
    "dns_exfiltration": 1.8,   # High-intent attack
    "brute_force":      1.4,
    "port_scan":        1.0,
    "anomaly":          1.2,
    "normal":           0.0,
}

STATUS_THRESHOLDS = {
    "trusted":     (70.0, 100.0),
    "suspicious":  (30.0, 69.9),
    "quarantined": (10.0, 29.9),
    "blocked":     (0.0,   9.9),
}


@dataclass
class TrustEvent:
    """A single trust-affecting event."""
    timestamp: float
    event_type: str          # "alert", "recovery", "manual_override"
    severity: str
    attack_type: str
    score_delta: float
    ml_confidence: float = 0.0
    note: str = ""


class TrustScoringEngine:
    """
    Manages per-device trust scores with temporal decay and event-driven updates.
    
    Design decisions:
    - Scores start at 100 (innocent until proven malicious)
    - Decay is logarithmic — small violations don't permanently blacklist
    - High-ML-confidence events cause larger deductions (model is more certain)
    - Scores recover via exponential decay toward baseline
    """

    def __init__(self):
        self._scores: dict[str, float] = {}         # ip → current score
        self._last_update: dict[str, float] = {}    # ip → timestamp
        self._event_history: dict[str, list[TrustEvent]] = {}

    def _init_device(self, ip: str) -> None:
        if ip not in self._scores:
            self._scores[ip] = float(settings.trust_score_max)
            self._last_update[ip] = time.time()
            self._event_history[ip] = []

    def get_score(self, ip: str) -> float:
        """Return current trust score, applying time-based recovery first."""
        self._init_device(ip)
        self._apply_decay(ip)
        return round(self._scores[ip], 2)

    def _apply_decay(self, ip: str) -> None:
        """
        Exponential recovery toward baseline (100).
        Formula: score += (100 - score) * (1 - e^(-rate * elapsed))
        This means: score recovers fast when very low, slows as it approaches 100.
        """
        now = time.time()
        elapsed = now - self._last_update[ip]
        if elapsed < 1:
            return

        current = self._scores[ip]
        baseline = float(settings.trust_score_max)
        rate = settings.trust_score_decay_rate / 3600   # Convert hourly rate to per-second

        # Exponential recovery
        recovery = (baseline - current) * (1 - math.exp(-rate * elapsed))
        self._scores[ip] = min(baseline, current + recovery)
        self._last_update[ip] = now

    def record_alert(
        self,
        ip: str,
        severity: str,
        attack_type: str,
        ml_confidence: float = 0.5,
    ) -> float:
        """
        Deduct trust points for a security event.
        Returns the new trust score.
        """
        self._init_device(ip)
        self._apply_decay(ip)

        base_deduction = SEVERITY_DEDUCTIONS.get(severity.lower(), 5.0)
        attack_multiplier = ATTACK_MULTIPLIERS.get(attack_type.lower(), 1.0)

        # ML confidence amplification: confident model = bigger deduction
        # At 50% confidence → 1.0x; at 100% confidence → 1.5x
        confidence_multiplier = 1.0 + (ml_confidence - 0.5)

        final_deduction = base_deduction * attack_multiplier * confidence_multiplier

        old_score = self._scores[ip]
        self._scores[ip] = max(
            float(settings.trust_score_min),
            old_score - final_deduction
        )

        event = TrustEvent(
            timestamp=time.time(),
            event_type="alert",
            severity=severity,
            attack_type=attack_type,
            score_delta=-final_deduction,
            ml_confidence=ml_confidence,
            note=f"Score: {old_score:.1f} → {self._scores[ip]:.1f}",
        )
        self._event_history[ip].append(event)

        new_score = self._scores[ip]
        new_status = self.get_status(ip)

        logger.info(
            f"Trust update | IP: {ip} | {old_score:.1f} → {new_score:.1f} "
            f"(-{final_deduction:.1f}) | {attack_type.upper()} | Status: {new_status}"
        )

        if new_status in ("quarantined", "blocked"):
            logger.warning(f"⚠️  Device {ip} status changed to {new_status.upper()}")

        return new_score

    def manual_override(self, ip: str, new_score: float, reason: str = "") -> float:
        """Analyst manually sets trust score (e.g., after false positive review)."""
        self._init_device(ip)
        old = self._scores[ip]
        self._scores[ip] = max(0.0, min(100.0, new_score))
        self._last_update[ip] = time.time()

        self._event_history[ip].append(TrustEvent(
            timestamp=time.time(),
            event_type="manual_override",
            severity="none",
            attack_type="none",
            score_delta=new_score - old,
            note=reason,
        ))
        logger.info(f"Manual override | IP: {ip} | {old:.1f} → {new_score:.1f} | Reason: {reason}")
        return self._scores[ip]

    def get_status(self, ip: str) -> str:
        """Derive device status label from current score."""
        score = self._scores.get(ip, 100.0)
        for status, (low, high) in STATUS_THRESHOLDS.items():
            if low <= score <= high:
                return status
        return "blocked"

    def get_all_scores(self) -> dict[str, dict]:
        """Return current scores for all tracked IPs — used by dashboard API."""
        result = {}
        for ip in list(self._scores.keys()):
            result[ip] = {
                "ip": ip,
                "score": self.get_score(ip),
                "status": self.get_status(ip),
                "event_count": len(self._event_history.get(ip, [])),
            }
        return result

    def get_device_history(self, ip: str) -> list[dict]:
        """Return event history for a specific device."""
        self._init_device(ip)
        return [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "severity": e.severity,
                "attack_type": e.attack_type,
                "score_delta": e.score_delta,
                "note": e.note,
            }
            for e in self._event_history.get(ip, [])
        ]


# ── Module-level singleton ───────────────────────────────────────────────────────
trust_engine = TrustScoringEngine()
