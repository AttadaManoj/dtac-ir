const STATUS_LABEL = {
  connecting: "Connecting…",
  live: "Live",
  reconnecting: "Reconnecting…",
  offline: "Offline",
};
const STATUS_COLOR = {
  connecting: "#F5A623",
  live: "#22D3A6",
  reconnecting: "#F5A623",
  offline: "#EF4444",
};

export default function Header({ connectionStatus, demoMode, onToggleDemo }) {
  const label = demoMode ? "Demo mode" : STATUS_LABEL[connectionStatus] || connectionStatus;
  const color = demoMode ? "#5B6B82" : STATUS_COLOR[connectionStatus] || "#5B6B82";

  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-hairline">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-trusted to-emerald-700 flex items-center justify-center font-mono font-bold text-void text-sm">
          D
        </div>
        <div>
          <h1 className="font-display font-semibold text-lg leading-none">DTAC-IR</h1>
          <p className="text-[11px] text-textdim leading-none mt-0.5">
            Dynamic Trust Assessment &amp; Control
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 font-mono text-xs">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: color, boxShadow: demoMode ? "none" : `0 0 6px ${color}` }}
          />
          <span style={{ color }}>{label}</span>
        </div>
        <button
          onClick={onToggleDemo}
          className="text-xs font-mono border border-hairline rounded px-3 py-1.5 text-textdim hover:text-textprimary hover:border-textdim transition-colors"
        >
          {demoMode ? "Use live backend" : "Switch to demo mode"}
        </button>
      </div>
    </header>
  );
}
