function Stat({ label, value, accent }) {
  return (
    <div className="flex-1 min-w-[140px] bg-panel border border-hairline rounded-lg px-4 py-3">
      <div className="text-[11px] uppercase tracking-wider text-textdim font-display">{label}</div>
      <div
        className="text-2xl font-mono font-medium mt-1"
        style={{ color: accent || "#E2E8F0" }}
      >
        {value}
      </div>
    </div>
  );
}

export default function StatsBar({ stats, engine }) {
  const breakdown = stats.status_breakdown || {};
  return (
    <div className="flex gap-3 flex-wrap">
      <Stat label="Devices" value={stats.total_devices ?? 0} />
      <Stat label="Avg trust" value={(stats.average_trust_score ?? 100).toFixed(1)} accent="#22D3A6" />
      <Stat label="Threats detected" value={engine.threats_detected ?? 0} accent="#EF4444" />
      <Stat label="Packets seen" value={(engine.total_packets ?? 0).toLocaleString()} />
      <Stat label="Quarantined" value={breakdown.quarantined ?? 0} accent="#FB7C3C" />
      <Stat label="Blocked" value={breakdown.blocked ?? 0} accent="#EF4444" />
    </div>
  );
}
