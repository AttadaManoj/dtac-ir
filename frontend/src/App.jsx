import { useEffect } from "react";
import { useDashboardStore } from "./store/useDashboardStore";
import Header from "./components/Header";
import StatsBar from "./components/StatsBar";
import TrustHexGrid from "./components/TrustHexGrid";
import ThreatTimeline from "./components/ThreatTimeline";
import AlertFeed from "./components/AlertFeed";

export default function App() {
  const {
    connectionStatus,
    demoMode,
    devices,
    alerts,
    stats,
    engine,
    history,
    bootstrap,
    connectLive,
    enableDemoMode,
    acknowledgeAlert,
  } = useDashboardStore();

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);

  return (
    <div className="min-h-screen text-textprimary">
      <Header
        connectionStatus={connectionStatus}
        demoMode={demoMode}
        onToggleDemo={() => (demoMode ? connectLive() : enableDemoMode())}
      />

      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        <StatsBar stats={stats} engine={engine} />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <section className="lg:col-span-2 bg-panel border border-hairline rounded-xl p-5">
            <h2 className="font-display text-sm uppercase tracking-wider text-textdim mb-4">
              Device trust grid
            </h2>
            <TrustHexGrid devices={devices} />
          </section>

          <section className="bg-panel border border-hairline rounded-xl p-5">
            <h2 className="font-display text-sm uppercase tracking-wider text-textdim mb-4">
              Live alerts
            </h2>
            <AlertFeed alerts={alerts} onAcknowledge={acknowledgeAlert} />
          </section>
        </div>

        <section className="bg-panel border border-hairline rounded-xl p-5">
          <h2 className="font-display text-sm uppercase tracking-wider text-textdim mb-4">
            Threat timeline
          </h2>
          <ThreatTimeline history={history} />
        </section>
      </main>
    </div>
  );
}
