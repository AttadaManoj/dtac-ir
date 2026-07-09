const SEVERITY_COLOR = {
  low: "#5B6B82",
  medium: "#F5A623",
  high: "#FB7C3C",
  critical: "#EF4444",
};

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.max(0, Math.floor(diff / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

export default function AlertFeed({ alerts, onAcknowledge }) {
  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto font-mono text-xs space-y-1 pr-1" style={{ maxHeight: 380 }}>
        {alerts.length === 0 ? (
          <div className="text-textdim py-10 text-center">No alerts yet. Standing by.</div>
        ) : (
          alerts.map((a) => {
            const color = SEVERITY_COLOR[a.severity?.toLowerCase?.()] || SEVERITY_COLOR.medium;
            return (
              <div
                key={a.id ?? `${a.src_ip}-${a.created_at}`}
                className="flex items-start gap-2 py-1.5 px-2 rounded border border-transparent hover:border-hairline hover:bg-panelraised/50 transition-colors"
              >
                <span
                  className="mt-1 w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ background: color, boxShadow: `0 0 6px ${color}` }}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between gap-2">
                    <span style={{ color }} className="uppercase font-semibold">
                      {a.attack_type || a.title}
                    </span>
                    <span className="text-textdim shrink-0">{timeAgo(a.created_at)}</span>
                  </div>
                  <div className="text-textdim truncate">
                    {a.src_ip}
                    {a.ml_confidence != null && (
                      <span className="ml-2">conf {(a.ml_confidence * 100).toFixed(0)}%</span>
                    )}
                  </div>
                </div>
                {onAcknowledge && a.id && !a.is_acknowledged && (
                  <button
                    onClick={() => onAcknowledge(a.id)}
                    className="text-textdim hover:text-trusted shrink-0 text-[10px] uppercase border border-hairline rounded px-1.5 py-0.5"
                  >
                    Ack
                  </button>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
