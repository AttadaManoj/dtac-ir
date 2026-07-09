import { useMemo, useState } from "react";

const STATUS_COLOR = {
  trusted: "#22D3A6",
  suspicious: "#F5A623",
  quarantined: "#FB7C3C",
  blocked: "#EF4444",
};

const HEX_SIZE = 34; // distance from center to vertex
const HEX_W = HEX_SIZE * Math.sqrt(3);
const HEX_H = HEX_SIZE * 2;

function hexPoints(cx, cy, size) {
  const pts = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 180) * (60 * i - 30);
    pts.push(`${cx + size * Math.cos(angle)},${cy + size * Math.sin(angle)}`);
  }
  return pts.join(" ");
}

/**
 * TrustHexGrid — the signature visual of DTAC-IR.
 * Each hexagon is one monitored device. Color encodes trust status,
 * fill opacity encodes the score itself (dimmer = lower trust),
 * and a hovered/selected hex reveals detail in a side readout.
 */
export default function TrustHexGrid({ devices }) {
  const [hovered, setHovered] = useState(null);

  const cols = 8;
  const positioned = useMemo(() => {
    return devices.map((d, i) => {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const xOffset = (row % 2) * (HEX_W / 2);
      const cx = col * HEX_W + HEX_W / 2 + xOffset + 10;
      const cy = row * (HEX_H * 0.75) + HEX_H / 2 + 10;
      return { ...d, cx, cy };
    });
  }, [devices]);

  const width = cols * HEX_W + HEX_W / 2 + 20;
  const rows = Math.ceil(devices.length / cols);
  const height = rows * (HEX_H * 0.75) + HEX_H / 2 + 20;

  const active = hovered ?? positioned[positioned.length - 1] ?? null;

  return (
    <div className="flex gap-6 items-start">
      <div className="overflow-auto flex-1" style={{ maxHeight: 420 }}>
        {devices.length === 0 ? (
          <div className="text-textdim font-mono text-sm py-16 text-center border border-dashed border-hairline rounded-lg">
            No devices observed yet — waiting for network activity.
          </div>
        ) : (
          <svg
            width="100%"
            viewBox={`0 0 ${Math.max(width, 100)} ${Math.max(height, 100)}`}
            role="img"
            aria-label="Device trust grid"
          >
            {positioned.map((d) => {
              const color = STATUS_COLOR[d.status] || STATUS_COLOR.trusted;
              const opacity = 0.25 + (d.score / 100) * 0.65;
              const isActive = hovered?.ip === d.ip;
              return (
                <g
                  key={d.ip}
                  onMouseEnter={() => setHovered(d)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: "pointer" }}
                >
                  <polygon
                    points={hexPoints(d.cx, d.cy, HEX_SIZE - 2)}
                    fill={color}
                    fillOpacity={opacity}
                    stroke={color}
                    strokeWidth={isActive ? 2.5 : 1}
                    style={{ transition: "all 0.2s ease" }}
                  />
                  <text
                    x={d.cx}
                    y={d.cy + 4}
                    textAnchor="middle"
                    fontSize="9"
                    fontFamily="'JetBrains Mono', monospace"
                    fill="#0A0E14"
                    fontWeight="700"
                  >
                    {Math.round(d.score)}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* Detail readout */}
      <div className="w-56 shrink-0 border-l border-hairline pl-6">
        <div className="text-xs uppercase tracking-wider text-textdim mb-2 font-display">
          {hovered ? "Selected device" : "Most recent"}
        </div>
        {active ? (
          <div className="space-y-2 font-mono text-sm">
            <div className="text-textprimary text-base">{active.ip}</div>
            <div className="flex items-center gap-2">
              <span
                className="inline-block w-2 h-2 rounded-full"
                style={{ background: STATUS_COLOR[active.status] }}
              />
              <span className="capitalize" style={{ color: STATUS_COLOR[active.status] }}>
                {active.status}
              </span>
            </div>
            <div className="text-textdim">
              Trust score: <span className="text-textprimary">{active.score?.toFixed?.(1) ?? active.score}</span>
            </div>
            {active.event_count !== undefined && (
              <div className="text-textdim">
                Events: <span className="text-textprimary">{active.event_count}</span>
              </div>
            )}
          </div>
        ) : (
          <div className="text-textdim font-mono text-sm">Hover a hex to inspect.</div>
        )}

        <div className="mt-6 space-y-1.5">
          {Object.entries(STATUS_COLOR).map(([status, color]) => (
            <div key={status} className="flex items-center gap-2 text-xs font-mono">
              <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: color }} />
              <span className="text-textdim capitalize">{status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
