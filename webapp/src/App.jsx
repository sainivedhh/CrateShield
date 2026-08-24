import React from 'react'
import { KV, Tags, RiskGauge, LevelBadge, SignalRow } from './components.jsx'

const API_BASE = 'http://localhost:8000'

const SIGNAL_LABELS = {
  build_network: 'Outbound network in build.rs',
  sensitive_env: 'Reads sensitive env vars',
  build_spawn: 'Spawns processes in build.rs',
  typo_score: 'Typosquats a popular crate',
  unsafe_kloc: 'High unsafe density',
  proc_macro_suspicious: 'Suspicious proc-macro imports',
}

const EXAMPLES = ['rand', 'tokio', 'cc', 'serde']

export default function App() {
  const [apiOk, setApiOk] = React.useState(null)
  const [name, setName] = React.useState('')
  const [version, setVersion] = React.useState('')
  const [loading, setLoading] = React.useState(false)
  const [status, setStatus] = React.useState({ msg: '', err: false })
  const [data, setData] = React.useState(null) // { predict, meta }
  const [rawOpen, setRawOpen] = React.useState(false)

  React.useEffect(() => {
    fetch(`${API_BASE}/docs`).then(() => setApiOk(true)).catch(() => setApiOk(false))
  }, [])

  async function runScan(overrideName) {
    const crateName = (overrideName ?? name).trim()
    if (!crateName) {
      setStatus({ msg: 'enter a crate name first', err: true })
      return
    }
    setLoading(true)
    setStatus({ msg: '', err: false })
    setData(null)

    try {
      const qs = new URLSearchParams({ name: crateName })
      if (version.trim() && !overrideName) qs.set('version', version.trim())

      const [predictRes, metaRes] = await Promise.allSettled([
        fetch(`${API_BASE}/api/predict?${qs.toString()}`),
        fetch(`${API_BASE}/api/crate/${encodeURIComponent(crateName)}`),
      ])

      if (predictRes.status !== 'fulfilled' || !predictRes.value.ok) {
        const detail =
          predictRes.status === 'fulfilled' ? (await predictRes.value.json()).detail : 'request failed'
        throw new Error(detail)
      }
      const predict = await predictRes.value.json()
      const meta = metaRes.status === 'fulfilled' && metaRes.value.ok ? await metaRes.value.json() : null

      setData({ predict, meta })
      setStatus({ msg: `scan complete · ${predict.crate}@${predict.version}`, err: false })
    } catch (err) {
      setStatus({
        msg: '✕ ' + (err.message || 'scan failed — is the crate name correct, and is the backend running?'),
        err: true,
      })
    } finally {
      setLoading(false)
    }
  }

  function onChip(exampleName) {
    setName(exampleName)
    setVersion('')
    runScan(exampleName)
  }

  return (
    <div className="wrap">
      <header>
        <div className="brand">
          <div className="brand-mark">CS</div>
          <div>
            <h1>CrateShield</h1>
            <small>rust supply-chain risk scanner</small>
          </div>
        </div>
        <div className="api-status">
          <span className={`dot ${apiOk === null ? '' : apiOk ? 'ok' : 'bad'}`} />
          <span>
            {apiOk === null ? 'checking backend…' : apiOk ? 'backend connected' : 'backend offline — run: uvicorn crateshield.api:app --reload'}
          </span>
        </div>
      </header>

      <p className="tagline">
        Enter a crates.io package name — CrateShield pulls the source, statically parses build.rs, unsafe/FFI usage,
        proc-macros, typosquatting distance and dependency shape with tree-sitter, and scores it against the trained detector.
      </p>

      <div className="search">
        <input
          type="text"
          placeholder="crate name, e.g. serde"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runScan()}
        />
        <input
          className="ver"
          type="text"
          placeholder="version (opt.)"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && runScan()}
        />
        <button disabled={loading} onClick={() => runScan()}>Scan</button>
      </div>

      <div className="examples">
        <span className="label">try:</span>
        {EXAMPLES.map((ex) => (
          <button className="chip" key={ex} onClick={() => onChip(ex)}>{ex}</button>
        ))}
      </div>

      <div id="status-line" className={status.err ? 'err' : ''}>{status.msg}</div>

      {loading && (
        <div className="scan-loader">
          <span>analyzing signals…</span>
          <div className="scan-bar" />
        </div>
      )}

      {data && <Result predict={data.predict} meta={data.meta} rawOpen={rawOpen} setRawOpen={setRawOpen} />}

      <footer>CrateShield · academic research tool · static analysis only, no code execution</footer>
    </div>
  )
}

function Result({ predict, meta, rawOpen, setRawOpen }) {
  const { crate, version, risk, signals } = predict
  const b = signals.build_rs || {}
  const u = signals.unsafe_ffi || {}
  const t = signals.typosquatting || {}
  const pm = signals.proc_macro || {}
  const dp = signals.dependencies || {}
  const md = signals.metadata || {}
  const snippets = b.flagged_snippets || []

  return (
    <div className="result">
      <div className="headline">
        <RiskGauge score={risk.risk_score} level={risk.risk_level} />
        <div className="headline-info">
          <div className="crate-name">{crate} <span className="ver">v{version}</span></div>
          <LevelBadge level={risk.risk_level} />
          <div className="desc">{meta?.description || ''}</div>
          <div className="source-note">scoring source: {risk.source}</div>
        </div>
      </div>

      <div className="grid">
        <div className="card">
          <h3>Registry Info</h3>
          {meta ? (
            <>
              <KV k="Latest version" v={meta.max_version} />
              <KV k="Downloads" v={meta.downloads?.toLocaleString?.() ?? meta.downloads} />
              <KV k="Versions published" v={meta.versions_count} />
              <KV k="Yanked versions" v={(meta.yanked_versions || []).length} />
              <KV k="Repository" html v={meta.repository ? <a className="reg-link" href={meta.repository} target="_blank" rel="noreferrer">{meta.repository}</a> : '—'} />
              <KV k="Created" v={meta.created_at?.slice(0, 10)} />
              <KV k="Last updated" v={meta.updated_at?.slice(0, 10)} />
            </>
          ) : <KV k="registry lookup unavailable" />}
        </div>

        <div className="card">
          <h3>Metadata</h3>
          <KV k="Name" v={md.name} />
          <KV k="Version" v={md.version} />
          <KV k="Authors" v={md.authors} />
          <KV k="Has build.rs" v={md.has_build_rs ? 'yes' : 'no'} />
          <KV k="Keywords" html v={<Tags items={md.keywords} />} />
        </div>

        <div className="card full-width">
          <h3>Risk Signal Breakdown</h3>
          {risk.rule_based.contributions.map((c, i) => (
            <SignalRow
              key={i}
              label={SIGNAL_LABELS[c.signal] || c.signal}
              triggered={c.triggered}
              weight={c.weight}
              note={c.note}
            />
          ))}
        </div>

        <div className="card">
          <h3>build.rs Analysis</h3>
          <KV k="Has build.rs" v={b.has_build_rs ? 'yes' : 'no'} />
          <KV k="Network calls" v={(b.network_calls || []).length} />
          <KV k="Process spawns" v={(b.process_spawns || []).length} />
          <KV k="Env reads (total)" v={(b.env_reads || []).length} />
          <KV k="Sensitive env reads" html v={<Tags items={b.sensitive_env_reads} />} />
          <KV k="Parse error" v={b.parse_error ? 'yes' : 'no'} />
        </div>

        <div className="card">
          <h3>Unsafe / FFI</h3>
          <KV k="Unsafe blocks" v={u.unsafe_block_count ?? 0} />
          <KV k="Unsafe fns" v={u.unsafe_fn_count ?? 0} />
          <KV k="Unsafe / KLOC" v={u.unsafe_per_kloc ?? 0} />
          <KV k="Lines of code" v={u.loc ?? 0} />
          <KV k="FFI declarations" v={(u.ffi_declarations || []).length} />
          <KV k="Syscall usage" html v={<Tags items={u.syscall_usage} />} />
        </div>

        <div className="card">
          <h3>Typosquatting</h3>
          <KV k="Similarity score" v={t.score ?? 0} />
          <KV k="Closest target" v={t.target} />
          <KV k="Edit distance" v={t.edit_distance} />
          <KV k="Substitution pattern" v={t.substitution_pattern} />
          <KV k="Flagged" v={t.flagged ? 'yes' : 'no'} />
        </div>

        <div className="card">
          <h3>Proc-Macro / Dependencies</h3>
          <KV k="Is proc-macro" v={pm.is_proc_macro ? 'yes' : 'no'} />
          <KV k="Suspicious PM imports" html v={<Tags items={pm.proc_macro_suspicious_imports} />} />
          <KV k="Dependency count" v={dp.count ?? 0} />
          <KV k="Dev dependencies" v={dp.dev_dependency_count ?? 0} />
          <KV k="Pinned versions" v={dp.pinned ? 'yes' : 'no'} />
        </div>

        {snippets.length > 0 && (
          <div className="card full-width">
            <h3>Flagged Code Snippets</h3>
            <div className="snippets">{snippets.join('\n\n---\n\n')}</div>
          </div>
        )}

        {risk.model && (
          <div className="card full-width">
            <h3>Trained Model — Feature Importances</h3>
            <KV k="Model malicious probability" v={`${(risk.model.malicious_probability * 100).toFixed(1)}%`} />
            {risk.model.feature_importances.map((f, i) => (
              <SignalRow key={i} label={f.feature} triggered={f.importance > 0} weight={f.importance} note="" />
            ))}
          </div>
        )}
      </div>

      <button className="raw-toggle" onClick={() => setRawOpen(!rawOpen)}>
        {rawOpen ? '▾' : '▸'} view raw signal JSON
      </button>
      {rawOpen && <pre className="raw-json">{JSON.stringify(predict, null, 2)}</pre>}
    </div>
  )
}
