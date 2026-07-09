import { create } from "zustand";
import { api, wsUrl } from "../lib/api";
import { createDemoEngine } from "../demo/simulate";

const MAX_RECONNECT_DELAY_MS = 15000;

export const useDashboardStore = create((set, get) => ({
  // ── Connection state ──────────────────────────────────────────────────
  connectionStatus: "connecting", // "connecting" | "live" | "reconnecting" | "offline"
  demoMode: false,
  demoEngine: null,
  _ws: null,
  _wsRetryDelay: 1000,
  _demoInterval: null,
  _bootstrapped: false, // guards against React StrictMode's double-effect in dev

  // ── Data ──────────────────────────────────────────────────────────────
  devices: [],
  alerts: [],
  stats: { total_devices: 0, status_breakdown: {}, average_trust_score: 100 },
  engine: { total_packets: 0, threats_detected: 0, active_hosts: 0 },
  history: [], // rolling timeline points: { t, threats, avgTrust }

  // ── Actions ───────────────────────────────────────────────────────────

  async bootstrap() {
    // React 18 StrictMode intentionally double-invokes effects in dev,
    // which previously caused two overlapping bootstrap() calls to race —
    // one landing in demo mode while the other kept a real WebSocket alive.
    if (get()._bootstrapped) return;
    set({ _bootstrapped: true });

    try {
      await api.health();
      get().connectLive();
    } catch {
      get().enableDemoMode();
    }
  },

  connectLive() {
    set({ connectionStatus: "connecting", demoMode: false });
    get()._stopDemo();
    get()._refreshRestData();
    get()._openSocket();
  },

  enableDemoMode() {
    get()._stopDemo(); // clear any existing interval in case this fires more than once
    get()._closeSocket();
    const engine = createDemoEngine();
    const snap = engine.snapshot();
    set({
      demoMode: true,
      connectionStatus: "live",
      demoEngine: engine,
      devices: snap.devices,
      alerts: snap.alerts,
      stats: snap.stats,
      engine: snap.engine,
    });
    const interval = setInterval(() => {
      const s = get().demoEngine?.tick();
      if (!s) return;
      set((state) => ({
        devices: s.devices,
        alerts: s.alerts,
        stats: s.stats,
        engine: s.engine,
        history: [
          ...state.history,
          {
            t: Date.now(),
            threats: s.engine.threats_detected,
            avgTrust: +s.stats.average_trust_score.toFixed(1),
          },
        ].slice(-40),
      }));
    }, 2000);
    set({ _demoInterval: interval });
  },

  _stopDemo() {
    const { _demoInterval } = get();
    if (_demoInterval) clearInterval(_demoInterval);
    set({ _demoInterval: null, demoEngine: null });
  },

  async _refreshRestData() {
    try {
      const [devicesRes, alertsRes, statsRes] = await Promise.all([
        api.devices(),
        api.alerts(),
        api.statsSummary(),
      ]);
      set({
        devices: devicesRes.devices || [],
        alerts: alertsRes.alerts || [],
        stats: statsRes,
      });
    } catch (e) {
      // Non-fatal — WebSocket may still bring live data
      console.warn("REST refresh failed", e);
    }
  },

  _openSocket() {
    if (get().demoMode) return; // never open a real socket while demo mode is active
    get()._closeSocket();
    let socket;
    try {
      socket = new WebSocket(wsUrl());
    } catch {
      get().enableDemoMode();
      return;
    }

    socket.onopen = () => {
      set({ connectionStatus: "live", _wsRetryDelay: 1000 });
    };

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "trust_update") {
          const devices = msg.devices || [];
          set((state) => {
            const avgTrust =
              devices.length > 0
                ? devices.reduce((sum, d) => sum + d.score, 0) / devices.length
                : 100;
            return {
              devices,
              history: [
                ...state.history,
                { t: Date.now(), threats: state.engine.threats_detected, avgTrust: +avgTrust.toFixed(1) },
              ].slice(-40),
            };
          });
        } else if (msg.type === "new_alert") {
          set((state) => ({ alerts: [msg.alert, ...state.alerts].slice(0, 50) }));
        }
      } catch (e) {
        console.warn("Bad WS payload", e);
      }
    };

    socket.onclose = () => {
      if (get().demoMode) return; // intentionally torn down for demo mode
      set({ connectionStatus: "reconnecting" });
      const delay = Math.min(get()._wsRetryDelay * 2, MAX_RECONNECT_DELAY_MS);
      set({ _wsRetryDelay: delay });
      setTimeout(() => {
        if (!get().demoMode) get()._openSocket();
      }, delay);
    };

    socket.onerror = () => {
      socket.close();
    };

    set({ _ws: socket });
  },

  _closeSocket() {
    const { _ws } = get();
    if (_ws) {
      _ws.onclose = null; // prevent auto-reconnect firing on manual close
      _ws.close();
    }
    set({ _ws: null });
  },

  async acknowledgeAlert(alertId) {
    if (get().demoMode) {
      set((state) => ({
        alerts: state.alerts.map((a) => (a.id === alertId ? { ...a, is_acknowledged: true } : a)),
      }));
      return;
    }
    await api.acknowledgeAlert(alertId);
    get()._refreshRestData();
  },
}));
