import { useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, Bell, Check, ChevronDown,
  CircleHelp, Clock3, Download, Globe2, LayoutDashboard, ListFilter, LockKeyhole,
  MoreHorizontal, Network, Search, Server, Shield, ShieldCheck, SlidersHorizontal,
  Sparkles, X,
} from 'lucide-react'
import { useStore, type Alert } from './store/useStore'
import './App.css'

type View = 'Overview' | 'Alerts' | 'Hosts' | 'Models' | 'Settings'
const navItems: { label: View; icon: typeof LayoutDashboard }[] = [
  { label: 'Overview', icon: LayoutDashboard }, { label: 'Alerts', icon: Bell },
  { label: 'Hosts', icon: Server }, { label: 'Models', icon: Sparkles }, { label: 'Settings', icon: SlidersHorizontal },
]
const severityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }
const formatTime = (value: string) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date)
}

function SeverityTag({ severity }: { severity: string }) {
  return <span className={`severity-tag severity-${severity.toLowerCase()}`}><i />{severity}</span>
}

function AlertTable({ alerts, onSelect }: { alerts: Alert[]; onSelect: (alert: Alert) => void }) {
  if (!alerts.length) return <div className="empty-state"><div className="empty-icon"><ShieldCheck size={22} /></div><strong>All quiet on the network</strong><span>Detections will appear here as the sensor streams events.</span></div>
  return <div className="table-wrap"><table className="alert-table"><thead><tr><th>Severity</th><th>Threat</th><th>Source</th><th>Destination</th><th>Confidence</th><th>Detected</th><th /></tr></thead><tbody>
    {alerts.map((alert, index) => <tr key={alert.alert_id || `${alert.timestamp}-${index}`} onClick={() => onSelect(alert)} tabIndex={0} onKeyDown={event => event.key === 'Enter' && onSelect(alert)}>
      <td><SeverityTag severity={alert.severity} /></td><td><span className="threat-name">{alert.threat_class.replaceAll('_', ' ')}</span><span className="protocol">{alert.five_tuple.proto} · {alert.five_tuple.dst_port}</span></td>
      <td className="mono">{alert.five_tuple.src_ip}<span className="protocol">:{alert.five_tuple.src_port}</span></td><td className="mono">{alert.five_tuple.dst_ip}<span className="protocol">:{alert.five_tuple.dst_port}</span></td>
      <td><div className="confidence"><span>{Math.round(alert.confidence * 100)}%</span><div><i style={{ width: `${Math.min(100, Math.max(0, alert.confidence * 100))}%` }} /></div></div></td><td className="time-cell">{formatTime(alert.detected_at || alert.timestamp)}</td><td><button className="icon-button row-more" aria-label="View detection"><MoreHorizontal size={17} /></button></td>
    </tr>)}
  </tbody></table></div>
}

function DetailDrawer({ alert, close }: { alert: Alert; close: () => void }) {
  const sensor = alert.evidence?.sensor as { feature_profile?: string; lgbm_feature_semantics?: string } | undefined
  return <div className="drawer-backdrop" onClick={close}><aside className="detail-drawer" onClick={event => event.stopPropagation()}>
    <div className="drawer-head"><div><span className="eyebrow">DETECTION DETAIL</span><h2>{alert.threat_class.replaceAll('_', ' ')}</h2></div><button className="icon-button" onClick={close} aria-label="Close details"><X size={18} /></button></div>
    <SeverityTag severity={alert.severity} /><p className="drawer-copy">Observed flow: {alert.five_tuple.src_ip}:{alert.five_tuple.src_port} → {alert.five_tuple.dst_ip}:{alert.five_tuple.dst_port} ({alert.five_tuple.proto}). This flow was flagged by the network monitoring pipeline with {Math.round(alert.confidence * 100)}% model confidence.</p>
    {sensor?.feature_profile === 'packet-derived-lab-v1' && <div className="lab-notice"><strong>Private lab sensor</strong><span>Packet-derived feature adapter; LightGBM fields are not CICFlowMeter-equivalent. Treat this result as a lab evaluation.</span></div>}
    <div className="detail-list"><div><span>Source address</span><strong className="mono">{alert.five_tuple.src_ip}:{alert.five_tuple.src_port}</strong></div><div><span>Destination</span><strong className="mono">{alert.five_tuple.dst_ip}:{alert.five_tuple.dst_port}</strong></div><div><span>Protocol</span><strong>{alert.five_tuple.proto}</strong></div><div><span>Confidence</span><strong>{Math.round(alert.confidence * 100)}%</strong></div><div><span>Detected</span><strong>{formatTime(alert.detected_at || alert.timestamp)}</strong></div><div><span>Inference latency</span><strong>{Number(alert.latency_ms || 0).toFixed(1)} ms</strong></div></div>
    {alert.explanation && <div className="explanation"><span className="eyebrow">MODEL EXPLANATION</span><p>{alert.explanation}</p></div>}
  </aside></div>
}

export default function App() {
  const alerts = useStore(state => state.alerts)
  const totalAlerts = useStore(state => state.totalAlerts)
  const flowsPerSecond = useStore(state => state.flowsPerSecond)
  const measurementWindowSeconds = useStore(state => state.measurementWindowSeconds)
  const metrics = useStore(state => state.metrics)
  const isConnected = useStore(state => state.isConnected)
  const [view, setView] = useState<View>('Overview')
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('All severities')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [range, setRange] = useState('Live stream')
  const critical = alerts.filter(alert => alert.severity === 'CRITICAL').length
  const high = alerts.filter(alert => alert.severity === 'HIGH').length
  const hosts = useMemo(() => new Set(alerts.flatMap(alert => [alert.five_tuple.src_ip, alert.five_tuple.dst_ip])).size, [alerts])
  const visibleAlerts = useMemo(() => alerts.filter(alert => {
    const matchesSeverity = severity === 'All severities' || alert.severity === severity.toUpperCase()
    const text = `${alert.threat_class} ${alert.five_tuple.src_ip} ${alert.five_tuple.dst_ip}`.toLowerCase()
    return matchesSeverity && text.includes(query.toLowerCase())
  }), [alerts, severity, query])
  const breakdown = useMemo(() => {
    const values: Record<string, number> = {}
    alerts.forEach(alert => { values[alert.threat_class] = (values[alert.threat_class] || 0) + 1 })
    return Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [alerts])
  const models = metrics?.models ?? []

  const exportAlerts = () => {
    if (!visibleAlerts.length) return
    const header = ['timestamp', 'severity', 'threat_class', 'source_ip', 'destination_ip', 'confidence']
    const rows = visibleAlerts.map(a => [a.timestamp, a.severity, a.threat_class, a.five_tuple.src_ip, a.five_tuple.dst_ip, a.confidence])
    const csv = [header, ...rows].map(row => row.map(value => `"${String(value).replaceAll('"', '""')}"`).join(',')).join('\n')
    const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); link.download = 'uniguard-alerts.csv'; link.click(); URL.revokeObjectURL(link.href)
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={() => setView('Overview')}><span className="brand-mark"><Shield size={19} strokeWidth={2.3} /></span><span><strong>uniguard</strong><small>THREAT INTELLIGENCE</small></span></a>
      <div className="workspace-switch"><span className="workspace-avatar">N</span><span><strong>Northstar Labs</strong><small>Security workspace</small></span><ChevronDown size={15} /></div>
      <span className="nav-caption">WORKSPACE</span>
      <nav className="side-nav" aria-label="Main navigation">{navItems.map(({ label, icon: Icon }) => <button key={label} className={`nav-link ${view === label ? 'active' : ''}`} onClick={() => setView(label)}><Icon size={17} /><span>{label}</span>{label === 'Alerts' && alerts.length > 0 && <b className="nav-count">{alerts.length}</b>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="sensor-card"><span className="sensor-icon"><Network size={16} /></span><div><strong>Edge sensor</strong><small>One-way inspection</small></div><span className={`sensor-dot ${isConnected ? 'online' : ''}`} /></div><button className="help-link"><CircleHelp size={16} /> Help & documentation</button><div className="user-card"><div className="user-avatar">AC</div><span><strong>Alex Chen</strong><small>Security analyst</small></span><MoreHorizontal size={18} /></div></div>
    </aside>

    <main className="main-area">
      <header className="topbar"><div className="breadcrumbs"><span>Workspace</span><span className="crumb-slash">/</span><strong>{view}</strong></div><div className="top-actions"><span className="top-date"><Clock3 size={14} /> Last updated {metrics?.timestamp ? formatTime(metrics.timestamp) : '—'}</span><span className={`connection-pill ${isConnected ? 'connected' : ''}`}><i />{isConnected ? 'Connected' : 'Offline'}</span><button className="top-icon" aria-label="Notifications"><Bell size={17} /><i /></button><div className="top-avatar">AC</div></div></header>
      <div className="page-content">
        <section className="page-heading"><div><div className="greeting"><span className="live-spark" /> NETWORK SECURITY <span>·</span> REAL-TIME MONITORING</div><h1>{view === 'Overview' ? 'Security overview' : view}</h1><p>{view === 'Overview' ? 'Here’s what’s happening across your network today.' : `Review ${view.toLowerCase()} across your monitored network.`}</p></div><div className="heading-actions"><button className="button button-secondary" onClick={exportAlerts}><Download size={15} /> Export report</button><button className="button button-primary" onClick={() => setView('Alerts')}><ListFilter size={15} /> View detections</button></div></section>

        {view === 'Settings' ? <section className="surface settings-panel"><div className="section-heading"><div><h2>Workspace settings</h2><p>Connection and monitoring status for this environment.</p></div></div><div className="settings-row"><div className="settings-icon"><Network size={18} /></div><div><strong>Detection stream</strong><span>WebSocket connection to the UniGuard analysis pipeline</span></div><span className={`connection-pill ${isConnected ? 'connected' : ''}`}><i />{isConnected ? 'Connected' : 'Offline'}</span></div><div className="settings-row"><div className="settings-icon"><LockKeyhole size={18} /></div><div><strong>Inspection mode</strong><span>Passive, one-way network monitoring</span></div><span className="mode-badge"><Check size={13} /> Active</span></div><div className="settings-row"><div className="settings-icon"><Sparkles size={18} /></div><div><strong>Ensemble models</strong><span>{models.length} models reported by the analysis pipeline</span></div><button className="button button-secondary" onClick={() => setView('Models')}>View models</button></div></section>
        : <>
          <section className="stats-grid" aria-label="Network metrics">
            <article className="stat-card"><div className="stat-top"><span>Flows/sec</span><span className="stat-icon blue"><Activity size={17} /></span></div><div className="stat-value">{Math.round(flowsPerSecond).toLocaleString()}<small>flows/sec</small></div><div className="stat-foot"><span className="stat-neutral"><Activity size={13} /> Current throughput</span><span>{measurementWindowSeconds}s rolling window</span></div></article>
            <article className="stat-card"><div className="stat-top"><span>Total detections</span><span className="stat-icon violet"><ShieldCheck size={17} /></span></div><div className="stat-value">{totalAlerts}<small>events</small></div><div className="stat-foot"><span className="stat-neutral"><ListFilter size={13} /> Active stream</span><span>Latest 100</span></div></article>
            <article className="stat-card"><div className="stat-top"><span>Critical & high</span><span className="stat-icon red"><AlertTriangle size={17} /></span></div><div className="stat-value">{critical + high}<small>events</small></div><div className="stat-foot"><span className="stat-negative"><ArrowUpRight size={13} /> {critical} critical</span><span>{high} high</span></div></article>
            <article className="stat-card"><div className="stat-top"><span>Batch processing time</span><span className="stat-icon green"><Clock3 size={17} /></span></div><div className="stat-value">{metrics?.processing_latency_ms != null ? metrics.processing_latency_ms.toFixed(1) : '—'}<small>ms</small></div><div className="stat-foot"><span className="stat-neutral"><Clock3 size={13} /> Model analysis</span><span>Last received batch</span></div></article>
          </section>

          {view === 'Overview' && <section className="overview-grid"><article className="surface breakdown-panel"><div className="section-heading"><div><h2>Threat activity</h2><p>Detections by threat classification</p></div><div className="select-wrap"><select value={range} onChange={event => setRange(event.target.value)} aria-label="Time range"><option>Live stream</option><option>Latest events</option></select><ChevronDown size={14} /></div></div>{breakdown.length ? <div className="breakdown-list">{breakdown.map(([name, count]) => <div className="breakdown-row" key={name}><span>{name.replaceAll('_', ' ')}</span><div className="breakdown-track"><i style={{ width: `${Math.max(5, count / Math.max(...breakdown.map(item => item[1])) * 100)}%` }} /></div><strong>{count}</strong></div>)}</div> : <div className="chart-empty"><div className="chart-empty-art"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /></div><strong>Waiting for network activity</strong><span>Threat classifications will appear as detections arrive.</span></div>}<div className="panel-foot"><span><i className="legend-dot" /> Detections</span><span>{alerts.length} events in current stream</span></div></article>
            <article className="surface models-summary"><div className="section-heading"><div><h2>Detection models</h2><p>Ensemble health status</p></div><button className="text-button" onClick={() => setView('Models')}>View all <span>→</span></button></div><div className="model-list">{(models.length ? models : [{ name: 'LightGBM + IForest', status: 'UNKNOWN', version: '—' }, { name: 'Beacon 1D-CNN', status: 'UNKNOWN', version: '—' }, { name: 'Char-CNN DNS', status: 'UNKNOWN', version: '—' }]).map((model, index) => <div className="model-row" key={model.name}><span className={`model-icon model-${index}`}><Sparkles size={15} /></span><span className="model-label"><strong>{model.name}</strong><small>v{model.version}</small></span><span className={`model-status ${model.status === 'REAL' ? 'ready' : model.status === 'ERROR' ? 'error' : ''}`}><i />{model.status === 'REAL' ? 'Operational' : model.status === 'ERROR' ? 'Error' : model.status === 'MOCK' ? 'Simulation' : 'Waiting'}</span></div>)}</div><div className="model-summary-foot"><span><Check size={14} /> Protected by ensemble analysis</span><span>{models.filter(model => model.status === 'REAL').length} / {models.length || 3} active</span></div></article></section>}

          <section className="surface detections-panel"><div className="section-heading detections-heading"><div><h2>{view === 'Hosts' ? 'Observed hosts' : view === 'Models' ? 'Detection models' : view === 'Alerts' ? 'All detections' : 'Recent detections'} <span className="heading-count">{view === 'Hosts' ? hosts : view === 'Models' ? models.length : visibleAlerts.length}</span></h2><p>{view === 'Hosts' ? 'Network endpoints identified in the live alert stream' : view === 'Models' ? 'Models contributing to threat classification' : 'Latest security events from your network sensors'}</p></div><div className="table-actions"><label className="search-box"><Search size={15} /><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search IP or threat" /></label><div className="select-wrap"><select value={severity} onChange={event => setSeverity(event.target.value)} aria-label="Filter by severity"><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><ChevronDown size={14} /></div></div></div>
            {view === 'Models' ? <div className="table-wrap"><table className="alert-table"><thead><tr><th>Model</th><th>Status</th><th>Version</th><th>Inferences</th><th>P95 latency</th></tr></thead><tbody>{models.map(model => <tr key={model.name}><td className="threat-name">{model.name}</td><td><span className={`model-status ${model.status === 'REAL' ? 'ready' : ''}`}><i />{model.status}</span></td><td className="mono">{model.version}</td><td>{(model.inference_count ?? 0).toLocaleString()}</td><td>{(model.p95_ms ?? 0).toFixed(1)} ms</td></tr>)}</tbody></table>{!models.length && <div className="empty-inline">Model health will be available when the analysis pipeline connects.</div>}</div>
            : view === 'Hosts' ? <div className="host-list">{Array.from(new Set(alerts.flatMap(alert => [alert.five_tuple.src_ip, alert.five_tuple.dst_ip]))).map(ip => { const count = alerts.filter(a => a.five_tuple.src_ip === ip || a.five_tuple.dst_ip === ip).length; const max = alerts.filter(a => a.five_tuple.src_ip === ip || a.five_tuple.dst_ip === ip).reduce((value, alert) => Math.max(value, severityRank[alert.severity] || 0), 0); return <div className="host-row" key={ip}><span className="host-symbol"><Globe2 size={16} /></span><strong className="mono">{ip}</strong><span className="host-events">{count} observed {count === 1 ? 'event' : 'events'}</span><SeverityTag severity={Object.keys(severityRank).find(key => severityRank[key] === max) || 'INFO'} /></div> })}{!hosts && <div className="empty-inline">Hosts will appear as network events are detected.</div>}</div>
            : <AlertTable alerts={visibleAlerts.slice(0, 50)} onSelect={setSelected} />}
            <div className="table-footer"><span>Showing <strong>{Math.min(50, view === 'Hosts' ? hosts : view === 'Models' ? models.length : visibleAlerts.length)}</strong> of <strong>{view === 'Hosts' ? hosts : view === 'Models' ? models.length : visibleAlerts.length}</strong> {view === 'Hosts' ? 'hosts' : view === 'Models' ? 'models' : 'detections'}</span><button className="text-button" onClick={() => setView(view === 'Alerts' ? 'Overview' : 'Alerts')}>{view === 'Alerts' ? 'Back to overview' : 'View all detections'} <span>→</span></button></div>
          </section>
        </>}
        <footer className="page-footer"><span>UniGuard <i>·</i> Passive network threat intelligence</span><span><LockKeyhole size={12} /> One-way inspection architecture</span></footer>
      </div>
    </main>
    {selected && <DetailDrawer alert={selected} close={() => setSelected(null)} />}
  </div>
}
