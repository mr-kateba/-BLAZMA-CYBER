/** Blazma Cyber mark — the Blazma family hexagon (same as Blazma Get / Blazma Boost) with a shield. */
export function Logo({ size = 38, className = 'brand-logo' }: { size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <defs>
        <linearGradient id="blazma-hex" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#FFB300" />
          <stop offset="1" stopColor="#FF3D00" />
        </linearGradient>
      </defs>
      <path d="M 50,3 L 91,26.5 L 91,73.5 L 50,97 L 9,73.5 L 9,26.5 Z" fill="url(#blazma-hex)" />
      <path d="M 50,20 L 71,28 L 71,47 C 71,61.5 62.5,71.5 50,78 C 37.5,71.5 29,61.5 29,47 L 29,28 Z" fill="#FFFFFF" />
      <path d="M 39.5,48.5 L 47,56 L 61,41.5" fill="none" stroke="#FF6D00" strokeWidth="6.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Decorative network constellation for page headers (deterministic, no randomness per render). */
export function Constellation() {
  const pts: Array<[number, number]> = [
    [40, 60], [120, 30], [200, 90], [260, 40], [330, 120], [400, 60], [470, 150], [540, 80], [610, 130], [680, 50],
    [90, 150], [170, 190], [300, 200], [430, 220], [560, 200], [650, 230], [720, 170],
  ];
  const links: Array<[number, number]> = [
    [0, 1], [1, 2], [2, 3], [3, 5], [2, 4], [4, 5], [5, 7], [4, 6], [6, 7], [7, 8], [8, 9], [0, 10], [10, 11], [11, 2],
    [11, 12], [12, 4], [12, 13], [13, 6], [13, 14], [14, 8], [14, 15], [15, 16], [16, 9],
  ];
  return (
    <svg className="constellation" viewBox="0 0 760 260" preserveAspectRatio="xMaxYMin slice" aria-hidden="true">
      <defs>
        <radialGradient id="cg" cx="70%" cy="0%" r="80%">
          <stop offset="0" stopColor="#2f86ff" stopOpacity="0.25" />
          <stop offset="1" stopColor="#2f86ff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <rect width="760" height="260" fill="url(#cg)" />
      <g stroke="#3b82f6" strokeOpacity="0.28" strokeWidth="1">
        {links.map(([a, b], i) => (
          <line key={i} x1={pts[a]![0]} y1={pts[a]![1]} x2={pts[b]![0]} y2={pts[b]![1]} />
        ))}
      </g>
      <g fill="#7dd3fc">
        {pts.map(([x, y], i) => (
          <circle key={i} cx={x} cy={y} r={i % 3 === 0 ? 2.6 : 1.6} opacity={i % 3 === 0 ? 0.9 : 0.55} />
        ))}
      </g>
    </svg>
  );
}
