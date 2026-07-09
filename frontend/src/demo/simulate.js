/**
 * Offline demo/simulation mode — generates plausible fake SOC activity so
 * the dashboard looks alive without a real backend or live network traffic.
 * Used for portfolio demos / interviews where you can't guarantee network access.
 */

const ATTACK_TYPES = ["port_scan", "syn_flood", "dns_exfiltration", "brute_force", "anomaly"];
const STATUS_ORDER = ["trusted", "suspicious", "quarantined", "blocked"];

function randomIp() {
  return `${rnd(10, 223)}.${rnd(0, 255)}.${rnd(0, 255)}.${rnd(1, 254)}`;
}
function rnd(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function statusFromScore(score) {
  if (score >= 70) return "trusted";
  if (score >= 30) return "suspicious";
  if (score >= 10) return "quarantined";
  return "blocked";
}

export function createDemoEngine(seedDeviceCount = 14) {
  let devices = Array.from({ length: seedDeviceCount }, () => {
    const score = rnd(55, 100);
    return {
      ip: randomIp(),
      score,
      status: statusFromScore(score),
      event_count: rnd(0, 6),
    };
  });

  let alerts = [];
  let alertId = 1;
  let totalPackets = rnd(4000, 9000);
  let threatsDetected = alerts.length;

  function tick() {
    // Occasionally mutate a random device's score (simulate ongoing scoring)
    if (Math.random() < 0.6) {
      const idx = rnd(0, devices.length - 1);
      const d = devices[idx];
      const delta = Math.random() < 0.7 ? -rnd(2, 12) : rnd(1, 6);
      const newScore = Math.max(0, Math.min(100, d.score + delta));
      devices[idx] = { ...d, score: newScore, status: statusFromScore(newScore) };

      if (delta < 0) {
        const attackType = ATTACK_TYPES[rnd(0, ATTACK_TYPES.length - 1)];
        const severity =
          newScore < 10 ? "critical" : newScore < 30 ? "high" : "medium";
        const alert = {
          id: alertId++,
          created_at: new Date().toISOString(),
          title: `${attackType.toUpperCase()} detected`,
          severity,
          attack_type: attackType.toUpperCase(),
          src_ip: d.ip,
          ml_confidence: +(0.6 + Math.random() * 0.39).toFixed(2),
        };
        alerts = [alert, ...alerts].slice(0, 50);
        threatsDetected += 1;
      }
    }

    // Occasionally introduce a brand-new device
    if (Math.random() < 0.08 && devices.length < 40) {
      const score = rnd(70, 100);
      devices = [
        ...devices,
        { ip: randomIp(), score, status: statusFromScore(score), event_count: 0 },
      ];
    }

    totalPackets += rnd(20, 200);

    return snapshot();
  }

  function snapshot() {
    return {
      devices: [...devices],
      alerts: [...alerts],
      stats: {
        total_devices: devices.length,
        status_breakdown: STATUS_ORDER.reduce((acc, s) => {
          acc[s] = devices.filter((d) => d.status === s).length;
          return acc;
        }, {}),
        average_trust_score:
          devices.reduce((sum, d) => sum + d.score, 0) / (devices.length || 1),
      },
      engine: {
        total_packets: totalPackets,
        threats_detected: threatsDetected,
        active_hosts: devices.length,
      },
    };
  }

  return { tick, snapshot };
}
