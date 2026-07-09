/**
 * Thin wrapper around the DTAC-IR backend REST API.
 * All calls are relative — Vite's dev proxy (see vite.config.js) forwards
 * /api and /health to the FastAPI backend on :8000, so this works both in
 * dev and once built + served behind the same origin as the backend.
 */

async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`${options.method || "GET"} ${path} failed: ${res.status}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),
  devices: () => request("/api/v1/devices/"),
  deviceTrust: (ip) => request(`/api/v1/devices/${ip}/trust`),
  overrideTrust: (ip, newScore, reason) =>
    request(`/api/v1/devices/${ip}/trust/override`, {
      method: "POST",
      body: JSON.stringify({ new_score: newScore, reason }),
    }),
  liveScores: () => request("/api/v1/devices/scores/live"),
  alerts: () => request("/api/v1/alerts/"),
  acknowledgeAlert: (alertId) =>
    request(`/api/v1/alerts/${alertId}/acknowledge`, { method: "PATCH" }),
  incidents: () => request("/api/v1/incidents/"),
  statsSummary: () => request("/api/v1/stats/summary"),
  mlStatus: () => request("/api/v1/ml/status"),
};

export function wsUrl() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/v1/ws/live`;
}
