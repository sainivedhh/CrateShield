import React from 'react'

export function KV({ k, v, html }) {
  const empty = v === undefined || v === null || v === ''
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className="v">{empty ? '—' : html ? v : String(v)}</span>
    </div>
  )
}

export function Tags({ items }) {
  if (!items || !items.length) return <>—</>
  return <>{items.map((t, i) => <span className="tag" key={i}>{t}</span>)}</>
}

const LEVEL_VAR = { LOW: '--low', MEDIUM: '--medium', HIGH: '--high', CRITICAL: '--critical' }

export function RiskGauge({ score, level }) {
  const circumference = 339.3
  const pct = Math.round((score || 0) * 100)
  const [offset, setOffset] = React.useState(circumference)
  React.useEffect(() => {
    const id = requestAnimationFrame(() => setOffset(circumference * (1 - (score || 0))))
    return () => cancelAnimationFrame(id)
  }, [score])
  const colorVar = LEVEL_VAR[level] || '--muted'
  return (
    <div className="gauge">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle className="gauge-bg" cx="66" cy="66" r="54" />
        <circle
          className="gauge-fg" cx="66" cy="66" r="54"
          stroke={`var(${colorVar})`}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="gauge-label">
        <div className="gauge-score">{pct}%</div>
        <div className="gauge-pct">RISK SCORE</div>
      </div>
    </div>
  )
}

export function LevelBadge({ level }) {
  const colorVar = LEVEL_VAR[level] || '--muted'
  return (
    <div
      className="level-badge"
      style={{
        background: `color-mix(in srgb, var(${colorVar}) 18%, transparent)`,
        color: `var(${colorVar})`,
        border: `1px solid var(${colorVar})`,
      }}
    >
      {level} RISK
    </div>
  )
}

export function SignalRow({ label, triggered, weight, note }) {
  return (
    <div className="signal-row">
      <div className="top">
        <div className="name">
          <span className={`indicator ${triggered ? 'on' : 'off'}`} />
          {label}
        </div>
        <span className="weight">weight {weight}</span>
      </div>
      <div className="note">{note}</div>
    </div>
  )
}
