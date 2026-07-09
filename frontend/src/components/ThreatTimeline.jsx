import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

function formatTime(t) {
  return new Date(t).toLocaleTimeString([], { minute: "2-digit", second: "2-digit" });
}

export default function ThreatTimeline({ history }) {
  const data = history.map((h) => ({ ...h, label: formatTime(h.t) }));

  return (
    <div className="h-52">
      {data.length < 2 ? (
        <div className="h-full flex items-center justify-center text-textdim font-mono text-sm">
          Collecting timeline data…
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="trustGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22D3A6" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#22D3A6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#EF4444" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1E2A3D" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="label"
              stroke="#5B6B82"
              fontSize={10}
              fontFamily="'JetBrains Mono', monospace"
              tickLine={false}
            />
            <YAxis stroke="#5B6B82" fontSize={10} fontFamily="'JetBrains Mono', monospace" tickLine={false} />
            <Tooltip
              contentStyle={{
                background: "#0F1620",
                border: "1px solid #1E2A3D",
                borderRadius: 8,
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
              }}
              labelStyle={{ color: "#5B6B82" }}
            />
            <Area
              type="monotone"
              dataKey="avgTrust"
              name="Avg trust"
              stroke="#22D3A6"
              fill="url(#trustGrad)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="threats"
              name="Threats"
              stroke="#EF4444"
              fill="url(#threatGrad)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
