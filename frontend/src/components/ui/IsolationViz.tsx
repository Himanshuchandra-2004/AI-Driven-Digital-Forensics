/** Animated explainer: random cuts isolate anomalies in just a few splits. */

const normal = Array.from({ length: 80 }, (_, i) => {
  const a = i * 2.4, r = 10 + ((i * 37) % 62);
  return [150 + Math.cos(a) * r * 1.5, 100 + Math.sin(a) * r] as const;
});
const anomalies = [[24, 22], [276, 28], [282, 172], [26, 178], [268, 104]] as const;

export default function IsolationViz({ contamination }: { contamination?: number | string }) {
  return (
    <div className="grid md:grid-cols-5 gap-5 items-center">
      <svg viewBox="0 0 300 200" className="iso-svg md:col-span-3" role="img" aria-label="Isolation Forest diagram">
        <defs>
          <radialGradient id="isoGlow"><stop offset="0" stopColor="#00c8ff" stopOpacity=".25" /><stop offset="1" stopColor="#00c8ff" stopOpacity="0" /></radialGradient>
        </defs>
        <ellipse cx="150" cy="100" rx="125" ry="85" fill="url(#isoGlow)" />
        <line x1="150" y1="0" x2="150" y2="200" className="iso-cut" style={{ animationDelay: '0s' }} />
        <line x1="0" y1="100" x2="300" y2="100" className="iso-cut c2" style={{ animationDelay: '.6s' }} />
        <line x1="238" y1="0" x2="238" y2="200" className="iso-cut c3" style={{ animationDelay: '1.2s' }} />
        <line x1="62" y1="0" x2="62" y2="200" className="iso-cut c2" style={{ animationDelay: '1.8s' }} />
        {normal.map(([x, y], i) => <circle key={i} cx={x} cy={y} r="2.8" fill="#00c8ff" opacity=".8" />)}
        {anomalies.map(([x, y], i) => (
          <g key={i}>
            <circle cx={x} cy={y} r="14" className="iso-ring" style={{ animationDelay: `${i * 0.4}s` }} />
            <circle cx={x} cy={y} r="4.5" fill="#ff4d8d" />
          </g>
        ))}
      </svg>
      <div className="md:col-span-2 space-y-4 text-sm">
        <p className="text-gray-400">Random cuts split the data. <b className="text-cyan-400">Normal points</b> sit in dense regions and need many cuts. <b className="text-pink-400">Anomalies</b> sit alone and are isolated in just a few — a short path means a high anomaly score.</p>
        <PathBar label="Normal traffic" depth={86} color="#00c8ff" note="~9 cuts" />
        <PathBar label="Anomalous traffic" depth={28} color="#ff4d8d" note="~3 cuts" />
        {contamination !== undefined && <p className="text-xs text-gray-500">Expected anomaly share (contamination): <span className="text-white font-mono">{String(contamination)}</span></p>}
      </div>
    </div>
  );
}

function PathBar({ label, depth, color, note }: { label: string; depth: number; color: string; note: string }) {
  return (
    <div>
      <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">{label}</span><span style={{ color }}>{note}</span></div>
      <div className="h-2 rounded-full bg-gray-800/50 overflow-hidden">
        <div className="h-full rounded-full bar-grow" style={{ width: `${depth}%`, background: color, boxShadow: `0 0 10px ${color}` }} />
      </div>
    </div>
  );
}
