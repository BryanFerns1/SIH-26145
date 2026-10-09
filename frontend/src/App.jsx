import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import AttackTimeline from './components/ui/attack-timeline';
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowDownUp, ArrowUpRight,
  Bell, BookOpen, Check, CheckCircle2, ChevronDown, ChevronLeft,
  ChevronRight, CircleHelp, Clock3, Cpu, Database, Download, Filter,
  Gauge, HardDrive, LayoutDashboard, LockKeyhole, Menu, MoreHorizontal,
  Network, Plus, Radio, RefreshCw, Search, Server, Settings2, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, Terminal, Waves, X, Zap,
} from 'lucide-react';


const LiveDataContext = createContext({ alerts: [], totalAlerts: 0, flowsPerSecond: 0, httpRequests: 0, models: [], connected: false });
const useLiveData = () => useContext(LiveDataContext);
const parseBackendDate = (value) => {
  if (!value) return NaN;
  const timestamp = /(?:Z|[+-]\d\d:\d\d)$/.test(value) ? value : `${value}Z`;
  return Date.parse(timestamp);
};

const threatGuidance = {
  DDOS: [
    'This flow was classified as a denial-of-service attack. The alert identifies suspicious traffic, but does not by itself confirm service impact or the full attack volume.',
    ['Enable upstream DDoS scrubbing or contact the transit provider if service is degraded.', 'Apply rate limits or narrowly scoped ACL/WAF rules to the targeted service.', 'Preserve flow records and check whether other destinations or source networks are affected.'],
  ],
  SCAN: [
    'This flow was classified as scanning or reconnaissance. It indicates probing activity; it does not alone prove that a host was compromised.',
    ['Rate-limit or block the source at the network edge when it is not an approved scanner.', 'Review the destination host for exposed services and close or restrict unnecessary ports.', 'Check nearby alerts for follow-on login attempts or exploit traffic.'],
  ],
  C2_BEACON: [
    'This flow was classified as possible command-and-control beaconing. Repeated timing patterns can indicate an infected host communicating with an external controller.',
    ['Investigate and, if confirmed, isolate the source endpoint under your incident-response process.', 'Block the destination indicator at DNS, proxy, and egress controls.', 'Search endpoint and network telemetry for the same destination and beacon interval.'],
  ],
  DNS_TUNNEL: [
    'This activity was classified as possible DNS tunneling, where DNS queries may carry hidden data or control traffic.',
    ['Restrict outbound DNS to approved recursive resolvers and block direct external DNS.', 'Review the queried domain and query volume; block the domain if confirmed malicious.', 'Preserve DNS logs and inspect the source endpoint for the process generating the queries.'],
  ],
  DGA: [
    'This activity was classified as a possible domain-generation algorithm lookup, often used by malware to find changing command servers.',
    ['Block confirmed malicious domains through protective DNS controls.', 'Prevent endpoints from bypassing approved DNS resolvers.', 'Investigate the source endpoint and search DNS logs for related generated domains.'],
  ],
  ANOMALY: [
    'The flow was flagged as anomalous compared with the model’s learned patterns. An anomaly is a review signal and is not, on its own, proof of an attack.',
    ['Compare the flow with the host’s normal role and recent maintenance or workload changes.', 'Review related flows and endpoint activity before deciding whether to contain the host.', 'If confirmed malicious, restrict the involved source or destination and preserve evidence.'],
  ],
};

function getThreatGuidance(threatClass) {
  return threatGuidance[threatClass] || [
    'The detection pipeline flagged this flow as suspicious. Confirm the activity with the sensor and endpoint context before treating it as a confirmed compromise.',
    ['Review the source, destination, protocol, and related alerts.', 'Apply a targeted block only after validating the indicator.', 'Preserve relevant network and endpoint logs for investigation.'],
  ];
}

function summarizeAlerts(alerts) {
  if (!alerts.length) return null;
  const classCounts = alerts.reduce((counts, alert) => {
    counts[alert.threatClass] = (counts[alert.threatClass] || 0) + 1;
    return counts;
  }, {});
  const maxCount = Math.max(...Object.values(classCounts));
  const dominantClasses = Object.keys(classCounts).filter((threat) => classCounts[threat] === maxCount).sort();
  const breakdown = Object.entries(classCounts).sort((a, b) => b[1] - a[1]).map(([threat, count]) => `${threat.replaceAll('_', ' ')}: ${count}`).join(', ');
  const lead = dominantClasses.length === 1
    ? `Most frequent classification: ${dominantClasses[0].replaceAll('_', ' ')} (${maxCount} alerts).`
    : `The feed is tied across ${dominantClasses.map((threat) => threat.replaceAll('_', ' ')).join(', ')} (${maxCount} alerts each).`;
  return {
    flows_received: null,
    alerts_generated: alerts.length,
    class_counts: classCounts,
    dominant_classes: dominantClasses,
    conclusion: `Across the latest ${alerts.length} backend detections, ${lead} Counts by class: ${breakdown}. Treat this as a model verdict and validate it against sensor and endpoint evidence.`,
  };
}

function mapAlert(alert) {
  const tuple = alert.five_tuple || {};
  const severity = String(alert.severity || 'INFO').toLowerCase();
  const sensor = alert.evidence?.sensor;
  const modelResults = (alert.models || []).map((model) => ({
    name: model.name,
    label: model.label,
    score: Number(model.score || 0),
    version: model.version,
  }));
  const title = String(alert.threat_class || 'UNKNOWN').replaceAll('_', ' ');
  const [conclusion, preventiveMeasures] = getThreatGuidance(alert.threat_class);
  const topModel = [...modelResults].sort((a, b) => b.score - a.score)[0];
  const supportingDetail = alert.explanation || (alert.rules_fired?.length
    ? `Rules fired: ${alert.rules_fired.join(', ')}`
    : sensor
      ? `${sensor.sensor || 'Sensor'} · ${sensor.termination || sensor.feature_profile || 'flow observed'}`
      : 'No supporting metadata supplied');
  return {
    id: alert.alert_id,
    timestamp: alert.detected_at || alert.timestamp,
    threatClass: String(alert.threat_class || 'UNKNOWN'),
    description: alert.explanation?.trim() || `The backend classified this ${tuple.proto || 'network'} flow as ${title} with ${Math.round((alert.confidence || 0) * 100)}% confidence${topModel ? `; its highest model score was ${topModel.label} from ${topModel.name}` : ''}. The backend did not provide a written explanation for this detection.`,
    conclusion: `${conclusion} Confidence: ${Math.round((alert.confidence || 0) * 100)}%.`,
    preventiveMeasures,
    modelResults,
    sensor: sensor || null,
    rulesFired: alert.rules_fired || [],
    mitre: alert.mitre || [],
    time: new Date(parseBackendDate(alert.detected_at || alert.timestamp)).toLocaleTimeString([], { timeZone: 'UTC', hour12: false, fractionalSecondDigits: 3 }),
    severity: severity[0].toUpperCase() + severity.slice(1),
    title,
    src: `${tuple.src_ip || '?'}:${tuple.src_port ?? ''}`,
    dst: `${tuple.dst_ip || '?'}:${tuple.dst_port ?? ''}`,
    proto: tuple.proto || 'Unknown',
    engine: (alert.models || []).map((model) => model.name).join(', ') || 'Ensemble pipeline',
    modelCount: alert.models?.length || 0,
    latencyMs: Number(alert.latency_ms || 0),
    confidence: `${Math.round((alert.confidence || 0) * 100)}%`,
    detail: supportingDetail,
  };
}

const navItems = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'alerts', label: 'Live Alerts', icon: AlertTriangle, badge: 'new' },
  { id: 'hosts', label: 'Enclave Hosts & Taps', icon: Network },
  { id: 'models', label: 'AI / ML Models', icon: Cpu },
  { id: 'hunting', label: 'Threat Hunting', icon: Search },
  { id: 'settings', label: 'Diode & Flow Settings', icon: SlidersHorizontal },
];

const detections = [
  { id: 'ALT-9482', time: '13:17:08.412', severity: 'Critical', title: 'C2 Beaconing', src: '10.240.12.84:51820', dst: '185.196.11.4:443', engine: 'Beacon 1D-CNN', confidence: '98.4%', detail: 'Periodicity delta: 60.02s ± 0.4s · Jitter 0.6%' },
  { id: 'ALT-9481', time: '13:16:54.198', severity: 'High', title: 'DNS Tunnel / DGA', src: '10.240.4.112:53411', dst: '8.8.8.8:53', engine: 'Char-CNN', confidence: '94.2%', detail: 'Entropy: 4.82 bits/char · Query length: 148B' },
  { id: 'ALT-9480', time: '13:16:32.004', severity: 'Critical', title: 'Encrypted Malware (JA4)', src: '10.240.18.9:49204', dst: '194.26.29.110:443', engine: 'JA4 Matcher', confidence: '96.8%', detail: 'JA4: t13d1516h2_8daaf6152771_b92d69e46a78' },
  { id: 'ALT-9479', time: '13:15:10.871', severity: 'High', title: 'Volumetric SYN Flood', src: 'Multiple (6.4k IPs)', dst: '10.240.0.1:80', engine: 'Isolation Forest', confidence: '91.5%', detail: 'Packet rate: 38,200 SYN/s · Zero ACK completion ratio' },
  { id: 'ALT-9478', time: '13:12:44.220', severity: 'Critical', title: 'Data Exfiltration Asymmetry', src: '10.240.8.44:44319', dst: '45.154.255.8:443', engine: 'LightGBM', confidence: '95.1%', detail: 'Byte ratio out/in: 42.8× · 842 MB egress / 19.6 MB ingress' },
];

const tapRows = [
  { id: 'TAP-01-RX', nic: '10G SFP+ · eth3 (pci@04:00.0)', target: 'Peering Enclave #01', vlan: 'VLAN 100–140 (Border Ingest)', rate: '1.42 Gbps', packets: '142,520 pkts/s', power: '−4.2 dBm', status: 'RX ONLY · TX CUT', tone: 'green' },
  { id: 'TAP-02-RX', nic: '40G QSFP+ · eth4 (pci@04:00.1)', target: 'Core DMZ Gateway #02', vlan: 'VLAN 200, 210, 240 (Services)', rate: '2.15 Gbps', packets: '210,040 pkts/s', power: '−5.1 dBm', status: 'RX ONLY · TX CUT', tone: 'green' },
  { id: 'TAP-03-RX', nic: '1G SFP-LX · eth5 (pci@05:00.0)', target: 'OT / SCADA Segment #04', vlan: 'VLAN 880 (Modbus / DNP3)', rate: '85 Mbps', packets: '9,200 pkts/s', power: '−3.8 dBm', status: 'RX ONLY · TX CUT', tone: 'green' },
  { id: 'TAP-04-STBY', nic: '10G SFP+ · eth6 (pci@05:00.1)', target: 'Secondary Peering Failover', vlan: 'Carrier detected · dark ingest', rate: '0 bps', packets: '0 pkts/s', power: '−26.4 dBm', status: 'HOT STANDBY', tone: 'amber' },
];

const models = [
  { name: 'LightGBM + IsolationForest', type: 'ML', version: 'v2.14-prod', status: 'Online · 99.8%', description: 'Tabular flow dynamics and volumetric anomaly detection', latency: '0.8 ms', memory: '142 MB', drift: '0.02 Stable', precision: '99.6%', recall: '98.9%', checksum: '9f8e…3c12', color: 'blue' },
  { name: 'Beacon 1D-CNN', type: 'CNN', version: 'v3.01-prod', status: 'Active · sub-line-rate', description: 'FFT and periodicity analysis for C2 heartbeats', latency: '1.6 ms', memory: '24% tensor load', drift: '0.01 Low', precision: '98.4%', recall: '97.8%', checksum: 'b24a…88ff', color: 'purple' },
  { name: 'Char-CNN & Byte Entropy', type: 'NLP', version: 'v1.9-prod', status: 'Active · zero-payload', description: 'High-entropy DNS tunneling and algorithmic domains', latency: '1.1 ms', memory: '88 MB', drift: '0.04 Stable', precision: '99.1%', recall: '98.2%', checksum: '7c12…49e1', color: 'green' },
  { name: 'JA4 / JA4+ Fingerprint Matcher', type: 'JA4', version: 'v4.2-prod', status: 'Active · hardware accelerated', description: 'Encrypted hello, cipher suites, and TLS extension vectors', latency: '0.3 ms', memory: '512 MB cache', drift: '0.00 Zero drift', precision: '99.9%', recall: '99.4%', checksum: '33e1…da90', color: 'amber' },
];

const metrics = {
  overview: [
    { label: 'Flows / sec Throughput', value: '18,420', unit: 'flows/sec', note: 'Live sensor flow starts', icon: Activity, color: 'blue' },
    { label: 'Total Detections', value: '0', unit: 'events', note: 'Confirmed attacks', icon: ShieldCheck, color: 'purple' },
    { label: 'Total Alerts', value: '38', unit: 'events today', note: 'Latest 100 classified', icon: Bell, color: 'amber' },
    { label: 'Critical & High Threats', value: '11', unit: 'events', note: '4 Critical · 7 High', icon: ShieldAlert, color: 'rose' },
    { label: 'Streaming Inference Latency', value: '4.2', unit: 'ms / batch', note: '< 10ms target', icon: Clock3, color: 'green' },
  ],
  alerts: [
    { label: 'Unacknowledged', value: '14', unit: 'active alerts', note: '4 critical · 7 high · 3 medium', icon: Bell, color: 'rose' },
    { label: 'Classification Speed', value: '3.8', unit: 'ms MTTC', note: 'Zero packet drops · p99 5.1ms', icon: Zap, color: 'green' },
    { label: 'Top Vector', value: 'Volumetric SYN Flood', unit: '', note: '36.8% stream · peak 1.42M pps', icon: Waves, color: 'amber' },
    { label: 'Hardware Air-Gap', value: '100%', unit: 'verified PHY', note: 'TX feedback: 0 packets', icon: ShieldCheck, color: 'green' },
  ],
  hosts: [
    { label: 'Total Tap Ingest', value: '4.85', unit: 'Gbps', note: '3 active taps · 99.999% ingest', icon: Radio, color: 'blue' },
    { label: 'Air-Gap Enforcement', value: '100%', unit: 'unidirectional', note: '0 packets TX return', icon: ShieldCheck, color: 'green' },
    { label: 'Ring Buffer Ingest', value: '0', unit: 'dropped packets', note: 'DPDK / AF_XDP · 18.4% fill', icon: HardDrive, color: 'blue' },
    { label: 'Tapped Segments', value: '14', unit: 'VLANs / 3 enclaves', note: 'Peering · DMZ · SCADA', icon: Network, color: 'purple' },
  ],
  models: [
    { label: 'Ensemble Throughput', value: '18,420', unit: 'flows/sec', note: '+4.2% · capacity 120k', icon: Activity, color: 'blue' },
    { label: 'Mean Inference Latency', value: '3.82', unit: 'ms', note: '< 10ms SLA · p99 5.14ms', icon: Zap, color: 'green' },
    { label: 'Active Model Ensemble', value: '4 / 4', unit: 'online', note: '100% health · 0 degraded', icon: Cpu, color: 'purple' },
    { label: 'Classification Performance', value: '99.2%', unit: 'F1 score', note: 'ROC-AUC 0.998 · zero drift', icon: Gauge, color: 'amber' },
  ],
  hunting: [
    { label: 'Indexed Flow Vectors', value: '4.28B', unit: 'vectors', note: '+128M / hr · zero overwrite', icon: Database, color: 'blue' },
    { label: 'Query Latency', value: '42', unit: 'ms', note: '< 100ms SLA · ClickHouse', icon: Clock3, color: 'green' },
    { label: 'Active IOC Correlators', value: '1,420', unit: 'IOCs', note: 'Air-gap offline synced', icon: Network, color: 'purple' },
    { label: 'Unmatched Anomalies', value: '27', unit: 'flagged', note: '4 critical · requires review', icon: AlertTriangle, color: 'amber' },
  ],
  settings: [
    { label: 'PHY Diode State', value: 'STRICT RX-ONLY', unit: '', note: 'TX pin cut · air-gapped', icon: ShieldCheck, color: 'green' },
    { label: 'DPDK Ring Allocation', value: '64', unit: 'GB', note: '< 12ns p99 jitter · NUMA 0', icon: HardDrive, color: 'blue' },
    { label: 'Optical Attenuation', value: '−4.2', unit: 'dBm', note: '80/20 split · 1310nm SMF', icon: Activity, color: 'green' },
    { label: 'Offline CTI Sync', value: 'Daily', unit: 'air-gapped', note: 'Ed25519 valid · 0 egress', icon: LockKeyhole, color: 'purple' },
  ],
};

function downloadCsv(filename, rows) {
  const text = rows.map((row) => row.map((cell) => `"${String(cell ?? '').replaceAll('"', '""')}"`).join(',')).join('\n');
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click();
  URL.revokeObjectURL(url);
}

function IconButton({ children, className = '', ...props }) {
  return <button className={`icon-button ${className}`} {...props}>{children}</button>;
}

function Button({ children, variant = 'secondary', icon: Icon, className = '', ...props }) {
  return <button className={`button button-${variant} ${className}`} {...props}>{Icon && <Icon size={16} />}{children}</button>;
}

function Pill({ children, tone = 'slate', dot = false, className = '' }) {
  return <span className={`pill pill-${tone} ${className}`}>{dot && <i />}{children}</span>;
}

function MetricCard({ item }) {
  const Icon = item.icon;
  return <article className={`metric-card ${String(item.value).length > 12 ? 'metric-card-long-value' : ''}`}>
    <div className="metric-top"><span>{item.label}</span><span className={`metric-icon icon-${item.color}`}><Icon size={17} /></span></div>
    <div className="metric-value-row"><strong className={item.color === 'rose' || item.color === 'green' ? `value-${item.color}` : ''}>{item.value}</strong>{item.unit && <span>{item.unit}</span>}</div>
    <div className="metric-foot"><span className={item.color === 'green' ? 'value-green' : item.color === 'rose' ? 'value-rose' : ''}>{item.note}</span><ArrowUpRight size={13} /></div>
  </article>;
}

function ScreenHeader({ eyebrow, title, description, actions, suffix }) {
  return <div className="screen-heading">
    <div className="screen-heading-copy">
      <div className="eyebrow"><span className="eyebrow-dot" />{eyebrow}</div>
      <div className="title-line"><h1>{title}</h1>{suffix}</div>
      <p>{description}</p>
    </div>
    <div className="heading-actions">{actions}</div>
  </div>;
}

function Card({ className = '', children }) { return <section className={`card ${className}`}>{children}</section>; }

function PanelHeading({ title, subtitle, action }) {
  return <div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>;
}

function Sidebar({ current, onNavigate, mobileOpen, setMobileOpen }) {
  const { totalAlerts } = useLiveData();
  return <>
    {mobileOpen && <button aria-label="Close navigation" className="mobile-scrim" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <div>
        <div className="brand"><span className="brand-mark"><Shield size={19} /></span><span><b>uniguard</b><small>THREAT INTELLIGENCE</small></span></div>
        <div className="nav-label">Workspace</div>
        <nav className="side-nav" aria-label="Workspace navigation">
          {navItems.map(({ id, label, icon: Icon, badge }) => <button key={id} className={`nav-item ${current === id ? 'nav-active' : ''}`} onClick={() => { onNavigate(id); setMobileOpen(false); }}>
            <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{badge && <Pill tone="rose" className="nav-badge">{totalAlerts} {badge}</Pill>}
          </button>)}
        </nav>
      </div>
      <div className="sidebar-bottom"><div className="sidebar-footer"><button><CircleHelp size={14} />Help & docs</button></div></div></aside>
  </>;
}

function TopBar({ onMenu }) {
  return <header className="topbar"><IconButton className="menu-button" aria-label="Open navigation" onClick={onMenu}><Menu size={20} /></IconButton></header>;
}

function Overview({ onNavigate, toast }) {
  const live = useLiveData();
  const detections = live.alerts;
  const models = live.models;
  const meanLatency = live.alerts.length ? live.alerts.reduce((total, alert) => total + alert.latencyMs, 0) / live.alerts.length : null;
  const overviewMetrics = metrics.overview.map((item, index) => ({ ...item, value: index === 0 ? Math.round(live.flowsPerSecond).toLocaleString() : index === 1 ? live.totalDetections.toLocaleString() : index === 2 ? live.totalAlerts.toLocaleString() : index === 3 ? String(live.alerts.filter((a) => ['Critical','High'].includes(a.severity)).length) : meanLatency === null ? '—' : meanLatency.toFixed(2), unit: index === 4 ? 'ms / alert' : item.unit, note: index === 0 ? 'New sensor flows / second · live' : index === 1 ? 'Pipeline confirmed attacks' : index === 2 ? 'Alerts reported by backend' : index === 3 ? 'Critical and high in recent feed' : 'Average backend inference latency' }));
  const batchSummary = live.batchSummary || summarizeAlerts(live.alerts);
  const hasBatchSummary = Boolean(live.batchSummary);
  const batchMeasures = [...new Set((batchSummary?.dominant_classes || []).flatMap((threat) => getThreatGuidance(threat)[1]))];
  return <>
    <ScreenHeader eyebrow="Network security · real-time zero-path ingest monitoring" title="Security overview" description="Here’s what’s happening across your air-gapped critical infrastructure network today."
      actions={<><Button icon={Download} onClick={() => downloadCsv('uniguard-overview.csv', [['ID','Time','Severity','Classification','Source','Destination','Confidence'], ...live.alerts.map((a) => [a.id,a.time,a.severity,a.title,a.src,a.dst,a.confidence])])}>Export alerts CSV</Button><Button variant="primary" icon={ShieldAlert} onClick={() => onNavigate('alerts')}>View active detections <span className="button-count">{live.totalAlerts}</span></Button></>} />
    <div className="metric-grid">{overviewMetrics.map((m) => <MetricCard key={m.label} item={m} />)}</div>
    <Card className="batch-conclusion-card"><PanelHeading title={hasBatchSummary ? 'Latest batch conclusion' : 'Overall detection conclusion'} subtitle={hasBatchSummary ? `${batchSummary.flows_received} flows · ${batchSummary.alerts_generated} model alerts` : batchSummary ? `Aggregated from the latest ${batchSummary.alerts_generated} backend alerts` : 'Waiting for backend detections'} action={batchSummary ? <Pill tone="slate">Model verdict</Pill> : null} />
      <p className="batch-conclusion-text">{batchSummary?.conclusion || 'The overall classification will appear here when detections arrive from the backend.'}</p>
      {batchSummary && Object.keys(batchSummary.class_counts || {}).length > 0 && <div className="batch-class-counts">{Object.entries(batchSummary.class_counts).sort((a, b) => b[1] - a[1]).map(([threat, count]) => <span key={threat}><b>{threat.replaceAll('_', ' ')}</b><i>{count}</i></span>)}</div>}
      {batchMeasures.length > 0 && <div className="batch-measures"><b>Suggested prevention for the leading classification</b><ul>{batchMeasures.map((measure) => <li key={measure}>{measure}</li>)}</ul></div>}
      <small className="batch-summary-note">{hasBatchSummary ? 'This aggregates model classifications from the latest ingest batch.' : 'This aggregates the latest alerts currently returned by the backend; it may cover more than one ingest batch.'} Confirm the incident with sensor and endpoint evidence.</small>
    </Card>
    <div className="overview-grid">
      <Card className="activity-card"><PanelHeading title="Threat activity classification" subtitle="Real-time passive sensor detections categorized by AI model family" action={<Pill tone="green" dot>RX active</Pill>} />
        <div className="activity-chart-space"><AttackTimeline alerts={live.alerts} /></div>
        <div className="vector-grid">{Object.entries(live.alerts.reduce((counts, alert) => ({ ...counts, [alert.title]: (counts[alert.title] || 0) + 1 }), {})).map(([label,count]) => <div className="vector-tile" key={label}><span className="vector-dot dot-rose" /><span className="vector-pct">{live.totalAlerts ? `${Math.round(count / live.totalAlerts * 100)}%` : '0%'}</span><b>{count}</b><small>{label}</small></div>)}</div>
      </Card>
      <Card><PanelHeading title="Detection models" subtitle="Streaming ensemble pipeline health" action={<button className="text-action" onClick={() => onNavigate('models')}>View all <ChevronRight size={15}/></button>} />
        <div className="model-mini-list">{models.map((m) => <div className={`model-mini mini-${m.color}`} key={m.name}><div className="model-mini-top"><span className={`model-logo logo-${m.color}`}>{m.type}</span><b>{m.name}</b><Pill tone="green" dot>{m.status.split(' · ')[0]}</Pill></div><p>{m.description}</p><div className="model-mini-foot"><span>Inference {m.latency}</span><span>Trained {m.version}</span></div></div>)}</div>
        <div className="ensemble-note"><ShieldCheck size={17}/><span><b>Protected by 4/4 ensemble models</b><small>Consensus confidence · 100%</small></span><CheckCircle2 size={16}/></div>
      </Card>
    </div>
    <DetectionTable toast={toast} onNavigate={() => onNavigate('alerts')} compact />
  </>;
}

function DetectionTable({ toast, compact = false }) {
  const { alerts: detections, totalAlerts } = useLiveData();
  const [selected, setSelected] = useState(null);
  const [severity, setSeverity] = useState('All severities');
  const [classifier, setClassifier] = useState('All classifiers');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const filtered = detections.filter((d) =>
    (severity === 'All severities' || d.severity === severity)
    && (classifier === 'All classifiers' || d.title === classifier)
    && `${d.id} ${d.title} ${d.src} ${d.dst} ${d.engine}`.toLowerCase().includes(search.toLowerCase()),
  );
  const pageSize = compact ? 5 : 20;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  return <Card className="table-card"><PanelHeading title={compact ? 'Recent passive detections' : 'Unacknowledged stream'} subtitle="Streamed directly via the backend flow analysis pipeline" action={<div className="table-heading-actions"><Pill tone="slate">{totalAlerts} active</Pill>{!compact && <Button icon={RefreshCw} onClick={() => toast('The live feed refreshes automatically.')}>Refresh</Button>}</div>} />
    <div className="table-tools"><label className="search-box"><Search size={15}/><input placeholder="Search IP, flow, or threat…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} /></label><label className="select-wrap"><Filter size={14}/><select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><ChevronDown size={14}/></label><label className="select-wrap"><select value={classifier} onChange={(e) => { setClassifier(e.target.value); setPage(1); }}><option>All classifiers</option>{[...new Set(detections.map((alert) => alert.title))].sort().map((name) => <option key={name}>{name}</option>)}</select><ChevronDown size={14}/></label><Button icon={RefreshCw} onClick={() => toast('The live feed refreshes automatically.')}>Refresh</Button></div>
    <div className="table-scroll"><table><thead><tr><th>Timestamp (UTC)</th><th>Flow identifier (src → dst)</th><th>Classification & subtype</th><th>ML confidence</th><th>Supporting metadata</th><th /></tr></thead><tbody>{visible.map((row) => <tr key={row.id} onClick={() => setSelected(row)} tabIndex={0} onKeyDown={(event) => event.key === 'Enter' && setSelected(row)}><td className="mono muted">{row.time}</td><td className="mono"><b>{row.src} →</b><br/>{row.dst}<small>Protocol: {row.proto}</small></td><td><Pill tone={row.severity.toLowerCase()}>{row.severity}</Pill><b className="classification">{row.title}</b><small>{row.engine}</small></td><td><b className="confidence">{row.confidence}</b><small>{row.modelCount} backend models</small></td><td className="muted feature-cell" title={row.detail}>{row.detail}</td><td><IconButton aria-label={`Show details for ${row.id}`} onClick={(e) => { e.stopPropagation(); setSelected(row); }}><MoreHorizontal size={17}/></IconButton></td></tr>)}</tbody></table></div>
    <div className="table-pagination"><span>Showing <b>{filtered.length ? (page - 1) * pageSize + 1 : 0}–{Math.min(page * pageSize, filtered.length)}</b> of <b>{filtered.length}</b> matching detections</span><div><button disabled={page === 1} onClick={() => setPage((p) => Math.max(1,p-1))}><ChevronLeft size={15}/>Previous</button><span>Page {page} of {pageCount}</span><button disabled={page >= pageCount} onClick={() => setPage((p) => Math.min(pageCount,p+1))}>Next<ChevronRight size={15}/></button></div></div>
    {selected && createPortal(<DetectionDetails alert={selected} onClose={() => setSelected(null)} />, document.body)}
  </Card>;
}

function Alerts({ toast }) {
  const { alerts: detections, totalAlerts } = useLiveData();
  const [filter, setFilter] = useState('All');
  const [selected, setSelected] = useState(null);
  const [checked, setChecked] = useState([]);
  const [audio, setAudio] = useState(true);
  const rows = detections.filter((d) => filter === 'All' || d.severity.toLowerCase() === filter.toLowerCase());
  const criticalCount = detections.filter((alert) => alert.severity === 'Critical').length;
  const highCount = detections.filter((alert) => alert.severity === 'High').length;
  const meanLatency = detections.length ? detections.reduce((total, alert) => total + alert.latencyMs, 0) / detections.length : null;
  const alertMetrics = metrics.alerts.map((item, index) => ({ ...item, value: index === 0 ? String(totalAlerts) : index === 1 ? (meanLatency === null ? '—' : meanLatency.toFixed(2)) : index === 2 ? (rows[0]?.title || '—') : '—', unit: index === 1 ? 'ms / alert' : item.unit, note: index === 0 ? 'Alerts reported by backend' : index === 1 ? 'Average backend inference latency' : index === 2 ? 'Most recent classification' : 'Not reported by backend' }));
  return <>
    <ScreenHeader eyebrow="Network security · real-time unidirectional alert feed · TAP-01_RX" title="Live Alerts" suffix={<Pill tone="rose">{totalAlerts} detections</Pill>} description="Triage current detections from the passive mirror stream. Classifications never send traffic back to the monitored network."
      actions={<><Button icon={Download} onClick={() => downloadCsv('uniguard-alerts.csv', [['ID','Time','Severity','Classification','Source','Destination','Confidence'], ...detections.map(d=>[d.id,d.time,d.severity,d.title,d.src,d.dst,d.confidence])])}>Export STIX 2.1 / TAXII</Button><Button icon={CheckCircle2} onClick={() => { toast(`${checked.length || 0} alerts acknowledged.`); setChecked([]); }}>Acknowledge ({checked.length})</Button></>} />
    <div className="metric-grid">{alertMetrics.map((m) => <MetricCard key={m.label} item={m}/>)}</div>
    <div className="alert-toolbar card"><label className="search-box"><Search size={15}/><input placeholder="Search IP, JA4 hash, domain…" /></label><div className="severity-filters">{['All','Critical','High','Med'].map((f) => <button key={f} className={filter===f ? 'filter-active' : ''} onClick={() => setFilter(f)}>{f}{f === 'All' ? ' 14' : <span>{f==='Critical'?'4':f==='High'?'7':'3'}</span>}</button>)}</div><div className="toolbar-end"><div className="chip-group compact-chips">{['15m','1h','6h','24h'].map((v,i)=><button key={v} className={i===0?'chip-active':''}>{v}</button>)}</div><button className={`stream-status ${audio?'':'stream-muted'}`} onClick={()=>setAudio(!audio)}><i/>{audio?'Audio chime: on':'Audio chime: off'}</button></div></div>
    <Card className="alert-table-card"><div className="alert-table-head"><b>UNACKNOWLEDGED STREAM</b><span>Live backend feed | refreshes every 3 seconds</span><div><Pill tone="rose">{criticalCount} critical</Pill><Pill tone="amber">{highCount} high</Pill></div></div><div className="table-scroll"><table><thead><tr><th><input aria-label="Select all alerts" type="checkbox" onChange={(e)=>setChecked(e.target.checked?rows.map(r=>r.id):[])} /></th><th>Severity</th><th>UTC timestamp</th><th>Alert classification</th><th>Flow identifier (src → dst)</th><th>ML engine</th></tr></thead><tbody>{rows.map(row=><tr key={row.id} className={selected?.id===row.id?'row-selected':''} onClick={()=>setSelected(row)}><td><input type="checkbox" aria-label={`Select ${row.id}`} checked={checked.includes(row.id)} onClick={(e)=>e.stopPropagation()} onChange={(e)=>setChecked((c)=>e.target.checked?[...c,row.id]:c.filter(id=>id!==row.id))}/></td><td><Pill tone={row.severity.toLowerCase()}>{row.severity}</Pill></td><td className="mono">{row.time}</td><td><b>{row.title}</b><small>{row.id}</small></td><td className="mono">{row.src} → {row.dst}</td><td>{row.engine}<small className="confidence">{row.confidence}</small></td></tr>)}</tbody></table></div><div className="table-pagination"><span>Showing {rows.length} of {totalAlerts} detections</span><div><button><ChevronLeft size={15}/>Previous</button><span>Page 1 of 3</span><button>Next<ChevronRight size={15}/></button></div></div></Card>
    {selected && <DetectionDetails alert={selected} onClose={() => setSelected(null)} />}
  </>;
}

function BurstChart() { return <svg className="burst-chart" viewBox="0 0 420 92" preserveAspectRatio="none" aria-label="Packet burst chart"><path d="M0 75 C45 74 62 66 102 71 S163 81 202 62 S252 61 282 28 S333 40 354 25 S397 28 420 12 L420 92 L0 92Z" fill="rgba(230,73,112,.14)"/><path d="M0 75 C45 74 62 66 102 71 S163 81 202 62 S252 61 282 28 S333 40 354 25 S397 28 420 12" fill="none" stroke="#e64970" strokeWidth="2.5"/></svg>; }

function Hosts({ toast }) {
  const [modal, setModal] = useState(false);
  return <>
    <ScreenHeader eyebrow="Network security · physical layer & passive ingest infrastructure" title="Enclave Hosts & Optical Taps" description="Real-time health, physical air-gap enforcement, and ingest bandwidth across four passive monitoring nodes."
      actions={<><Button icon={Download} onClick={()=>downloadCsv('phy-audit.csv',[['Tap','Target','Throughput','Optical power','Air-gap'],...tapRows.map(r=>[r.id,r.target,r.rate,r.power,r.status])])}>Export PHY audit report</Button><Button variant="primary" icon={Plus} onClick={()=>setModal(true)}>Add physical tap config</Button></>} />
    <div className="metric-grid">{metrics.hosts.map((m)=><MetricCard key={m.label} item={m}/>)}</div>
    <Card className="architecture-card"><PanelHeading title="Passive optical tap & hardware diode architecture" subtitle="Hardware-enforced unilateral transmission path. Frames cannot re-enter the tapped network." action={<Pill tone="blue">80 / 20 optical beam splitter</Pill>}/>
      <div className="architecture-flow"><div className="architecture-node"><div className="node-heading">Source optical links <Pill tone="slate">Untrusted core</Pill></div><div className="node-item"><span className="node-icon icon-blue"><Network size={17}/></span><span><b>Border Gateway AS65001</b><small>100G trunk · VLAN 100, 200, 310</small><em>● Active · 24.8 Tb/day</em></span></div><div className="node-item"><span className="node-icon icon-purple"><Network size={17}/></span><span><b>Core DMZ Spine #02</b><small>40G MPO ingress line</small><em>VLAN 40–48 · bidirectional line</em></span></div></div>
        <div className="flow-arrow"><span>100% flux</span><ArrowDownUp size={18}/><small>Optical in</small></div>
        <div className="architecture-node node-isolator"><div className="node-heading">Passive isolator & diode <Pill tone="green">PHY air-gap sealed</Pill></div><div className="node-item"><span className="node-icon icon-green"><ShieldCheck size={18}/></span><span><b>FBT optical coupler (80:20)</b><small>Insertion loss · 1.1 dB</small></span></div><div className="beam-split"><div><b>80% live transit</b><small>Transparent passthrough to core</small></div><div><b>20% RX-only mirror</b><small>−4.2 dBm optical power</small></div></div><div className="cut-fiber"><span>TX fiber core</span><b><X size={15}/> Physically severed · zero return risk</b></div></div>
        <div className="flow-arrow flow-rx"><span>RX only</span><ArrowDownUp size={18}/><small>One-way mirror</small></div>
        <div className="architecture-node"><div className="node-heading">Passive enclave cluster <Pill tone="blue">Northstar #01</Pill></div><div className="node-item"><span className="node-icon icon-blue"><Server size={17}/></span><span><b>Kernel bypass DPDK RX</b><small>0.12µs ingest latency</small><em>Dual Mellanox ConnectX-6 Dx</em></span></div><div className="node-item"><span className="node-icon icon-purple"><Cpu size={17}/></span><span><b>Stream demux & ML inference</b><small>Direct memory-pinned queues</small><em>LightGBM + Beacon 1D-CNN</em></span></div></div></div>
    </Card>
    <Card className="table-card"><PanelHeading title="Active optical tap ports" subtitle="Four channels configured · total RX 361.7k packets/s" action={<Pill tone="green" dot>3 active · 1 standby</Pill>}/><div className="table-scroll"><table><thead><tr><th>Tap ID / interface</th><th>Target subnet / trunk</th><th>Throughput / rate</th><th>RX optical power</th><th>Air-gap status</th><th>Drops</th></tr></thead><tbody>{tapRows.map((r)=><tr key={r.id}><td><b className="mono">{r.id}</b><small>{r.nic}</small></td><td><b>{r.target}</b><small>{r.vlan}</small></td><td><b>{r.rate}</b><small>{r.packets}</small></td><td className={r.tone==='green'?'value-green':'value-amber'}>{r.power}</td><td><Pill tone={r.tone}>{r.status}</Pill></td><td>0</td></tr>)}</tbody></table></div></Card>
    <div className="host-lower-grid"><Card><PanelHeading title="Isolated enclave compute nodes" subtitle="Out-of-band host telemetry · IPMI verified"/><div className="compute-node"><span className="node-icon icon-blue"><Server size={18}/></span><div><b>Worker node 01</b><small>AMD EPYC 9654 · 64 cores · 256 GB ECC</small></div><Pill tone="green" dot>Healthy</Pill></div><div className="compute-stats"><span>CPU load <b>24%</b></span><span>Core temp <b>48°C</b></span><span>Hugepages <b>64.2 GB</b></span></div></Card><Card><PanelHeading title="Optical PHY diagnostics" subtitle="Live DDM sensors"/><div className="diag-list"><p><span>TAP-01 RX power</span><b className="value-green">−4.2 dBm</b></p><p><span>Back reflection</span><b>−55.2 dB</b></p><p><span>Transceiver temp</span><b>38.4°C · nominal</b></p><p><span>TX laser bias</span><b className="value-green">0.00 mA · off</b></p></div></Card></div>
    {modal&&<Modal title="Add physical tap configuration" onClose={()=>setModal(false)}><p className="modal-copy">Register a passive RX-only optical tap. Hardware TX isolation remains enforced.</p><label className="form-label">Tap name<input placeholder="e.g. TAP-05-RX"/></label><label className="form-label">Target enclave<select><option>Peering Enclave #01</option><option>Core DMZ Gateway #02</option><option>OT / SCADA Segment #04</option></select></label><div className="modal-actions"><Button onClick={()=>setModal(false)}>Cancel</Button><Button variant="primary" onClick={()=>{setModal(false);toast('Tap configuration saved locally. Connect a backend to provision hardware.')}}>Save configuration</Button></div></Modal>}
  </>;
}

function Models({ toast }) {
  const { models } = useLiveData();
  return <>
    <ScreenHeader eyebrow="Network security · passive real-time inference · zero-feedback ML cluster" title="AI & ML Detection Models" description="Ensemble engines classify threats from zero-copy ring buffers with no packet interception."
      actions={<><Button icon={Download} onClick={()=>downloadCsv('model-registry.csv',[['Model','Version','Status','Latency','Precision','Recall'],...models.map(m=>[m.name,m.version,m.status,m.latency,m.precision,m.recall])])}>Export model registry</Button><Button variant="primary" icon={RefreshCw} onClick={()=>toast('Offline retraining requires an enclave deployment connection.')}>Retrain & deploy offline weights</Button></>} />
    <div className="metric-grid">{metrics.models.map((m)=><MetricCard key={m.label} item={m}/>)}</div>
      <div className="model-grid">{models.map((m)=><Card className="model-detail-card" key={m.name}><div className="model-detail-heading"><div className="model-title"><span className={`model-logo logo-${m.color}`}>{m.type}</span><div><h2>{m.name}</h2><Pill tone="slate">{m.version}</Pill></div></div><Pill tone={m.status === 'REAL' ? 'green' : 'rose'} dot>{m.status}</Pill></div><p className="model-description">{m.description}</p><div className="model-spec-grid"><div><small>LATENCY (P95)</small><b>{m.latency}</b></div><div><small>FOOTPRINT</small><b>{m.memory}</b></div><div><small>DRIFT (PSI)</small><b title="PSI compares the model's first 50 live prediction scores with its most recent 50.">{m.drift}</b></div></div><div className="feature-inspected"><small>FEATURES INSPECTED</small><p>{m.features}</p></div><div className="model-detail-footer"><span>Precision <b>{m.precision}</b> ? Recall <b>{m.recall}</b></span><span>{m.inferenceCount.toLocaleString()} inferences</span></div><button className="model-drill" onClick={()=>toast(`${m.name} telemetry opened.`)}>View telemetry <ArrowUpRight size={14}/></button></Card>)}</div>
  </>;
}

function Hunting({ toast }) {
  const [query, setQuery] = useState("SELECT * FROM enclave_flows\nWHERE proto = 'TLS' AND ja4_hash NOT IN (known_allowlist)\nAND flow_duration > 300s ORDER BY risk_score DESC");
  const [ran, setRan] = useState(false);
  const presets = ["Long C2 heartbeat jitter (<0.05)","Rare JA4+ fingerprints (< 5 hits)","Non-standard port TLS","DGA entropy > 3.8"];
  return <>
    <ScreenHeader eyebrow="Network security · passive retrospective forensics · ClickHouse read-only mode" title="Threat Hunting & Query Workbench" description="Search historical ring-buffer flows, correlate unseen C2 beacons, and run sub-second JA4 queries."
      actions={<><Button icon={Download} onClick={()=>downloadCsv('uniguard-hunt.csv',[['Time','Threat','Flow','JA4','Score'],['13:42:19.402','Sliver C2 periodicity','10.14.2.148 → 185.220.101.5','t13d1516h2_8da679e7627b','98.6%']])}>Export STIX / MISP intel</Button><Button variant="primary" icon={Plus} onClick={()=>toast('Investigation created locally.')}>New threat investigation</Button></>} />
    <div className="metric-grid">{metrics.hunting.map((m)=><MetricCard key={m.label} item={m}/>)}</div>
    <Card className="query-card"><div className="query-header"><div><Terminal size={17}/><b>ENCLAVE FLOW HUNT CONSOLE</b><Pill tone="purple">CLICKHOUSE SQL · AIR-GAP RO MODE</Pill></div><span className="query-shards"><i/>Active query shards 8/8</span></div><div className="preset-row"><span>Hypothesis presets</span>{presets.map((p,i)=><button className={i===0?'preset-selected':''} key={p} onClick={()=>setQuery(i===0?"SELECT * FROM enclave_flows WHERE beacon_jitter < 0.05 ORDER BY risk_score DESC":i===1?"SELECT ja4_hash, count(*) FROM enclave_flows GROUP BY ja4_hash HAVING count(*) < 5 ORDER BY risk_score DESC":i===2?"SELECT * FROM enclave_flows WHERE proto = 'TLS' AND dst_port NOT IN (443, 8443) ORDER BY risk_score DESC":"SELECT * FROM dns_flows WHERE domain_entropy > 3.8 ORDER BY risk_score DESC")}>{p}</button>)}</div><div className="sql-editor"><div className="sql-line-no">hunt &gt;</div><textarea aria-label="Threat hunting SQL query" value={query} onChange={(e)=>setQuery(e.target.value)} spellCheck="false"/><span className="sql-caret"/></div><div className="query-options"><label>Window<select><option>Last 24 hours</option><option>Last hour</option><option>Last 7 days</option></select><ChevronDown size={13}/></label><label>Enclave tap<select><option>All active taps (#01, #02, #03)</option><option>Peering #01</option><option>Core DMZ #02</option></select><ChevronDown size={13}/></label><span>Read-only · max 10,000 rows</span><Button variant="primary" icon={Terminal} onClick={()=>{setRan(true);toast('Query executed against sample data. Connect ClickHouse to run live searches.')}}>Run query <kbd>Shift + Enter</kbd></Button></div></Card>
    <div className="hunting-results-grid"><Card className="table-card"><PanelHeading title="Hunting query results" subtitle={`${ran?'3':'27'} flow vectors identified from ClickHouse retrospective scan`} action={<Button icon={Filter} onClick={()=>toast('Result filters opened.')}>Filter actions</Button>}/><div className="table-scroll"><table><thead><tr><th>UTC time</th><th>Threat hypothesis</th><th>Flow tuple</th><th>JA4 / signature</th><th>ML score</th></tr></thead><tbody>{[['13:42:19.402','Sliver C2 periodicity','10.14.2.148 → 185.220.101.5','t13d1516h2_8da679e7627b','98.6%'],['13:41:58.912','High-entropy DGA DNS','10.14.0.88 → 8.8.8.8','q53_00f8921a4','94.2%'],['13:40:02.115','Suspicious TLS handshake','10.14.1.205 → 91.240.118.172','t13d190800_443_ae01','91.0%']].map((r)=><tr key={r[0]}><td className="mono">{r[0]}</td><td><b>{r[1]}</b><small>Passive flow vector</small></td><td className="mono">{r[2]}</td><td className="mono muted">{r[3]}</td><td className="confidence">{r[4]}</td></tr>)}</tbody></table></div></Card><Card className="flow-forensics"><div className="selected-alert-top"><Pill tone="blue">#HUNT-8041</Pill><Pill tone="green" dot>Diode verified</Pill></div><h2>Sliver C2 periodicity breakdown</h2><p>High-confidence beacon pattern detected over TLS 1.3 encapsulation.</p><div className="forensic-score"><span>1D-CNN score</span><b>98.6%</b><i><em/></i></div><div className="diag-list"><p><span>Inter-arrival jitter</span><b>0.012s</b></p><p><span>Sleep window</span><b>60.0s ± 2%</b></p><p><span>Transport</span><b>TLS 1.3</b></p></div></Card></div>
  </>;
}

function Settings({ toast }) {
  const [latch, setLatch] = useState(true);
  const [sensitivity, setSensitivity] = useState(-12);
  const [watchdog, setWatchdog] = useState(true);
  const [policy, setPolicy] = useState(true);
  return <>
    <ScreenHeader eyebrow="Network security · hardware air-gap policy · ring buffer calibration" title="Diode & Flow Ingest Settings" description="Configure optical tap ratios, DPDK ring buffers, TX lockout verification, and offline CTI sync."
      actions={<><Button icon={ShieldCheck} onClick={()=>toast('Hardware audit passed · RX-only state verified.')}>Audit hardware state</Button><Button variant="primary" icon={LockKeyhole} onClick={()=>toast('Settings saved locally. Connect an enclave backend to commit hardware changes.')}>Commit enclave config</Button></>} />
    <div className="metric-grid">{metrics.settings.map((m)=><MetricCard key={m.label} item={m}/>)}</div>
    <div className="settings-layout"><div className="settings-main"><Card><div className="settings-panel-title"><span className="node-icon icon-green"><ShieldCheck size={18}/></span><span><h2>Hardware data diode enforcement</h2><p>Physical-layer unidirectional enforcement mechanisms</p></span><Pill tone="slate">EEPROM locked</Pill></div>
      <SettingRow title="Strict unidirectional enclave lockout" description="Hardware-level laser driver disablement on the physical transceiver." status="Non-negotiable hardware latch active"><Switch checked={latch} onChange={()=>setLatch(!latch)} label="Strict unidirectional lockout"/></SettingRow>
      <SettingRow title="Optical RX photoreceiver sensitivity trigger" description="Set the receive sensitivity threshold for the passive optical tap."><span className="slider-value">{sensitivity} dBm</span></SettingRow><input className="sensitivity-range" type="range" min="-18" max="0" value={sensitivity} onChange={(e)=>setSensitivity(Number(e.target.value))}/><div className="range-labels"><span>−18 dBm · ultra-sensitive</span><b>−12 dBm · standard 80/20</b><span>0 dBm · high ingest</span></div>
      <SettingRow title="Tamper & link continuity watchdog" description="Continuously monitor the RX SFP optical fiber path for disconnection or tampering." status="3 link events in 720h"><Switch checked={watchdog} onChange={()=>setWatchdog(!watchdog)} label="Tamper and continuity watchdog"/></SettingRow><SettingRow title="PHY loopback prevention circuit" description="Hardware-level control preventing optical feedback into the production network."><Pill tone="green">Disabled · hardware protected</Pill></SettingRow>
    </Card>
    <Card><div className="settings-panel-title"><span className="node-icon icon-blue"><HardDrive size={18}/></span><span><h2>Zero-feedback DPDK & kernel-bypass ring buffer</h2><p>Zero-copy memory allocation for high-throughput passive inspection</p></span><Pill tone="blue">DPDK v23.11</Pill></div><div className="config-grid">{[['Worker cores dedicated','16 cores · pinned 0–15','Isolated from kernel scheduler'],['Queue descriptors (RX ring)','4096 RX descriptors / interface','Zero-copy mbuf memory pools'],['Flow vector slicing strategy','64-byte tuple + JA4 hash','Payload contents never stored'],['PCAP retention ring buffer','72h / 14.7 TB pooled','Sealed forensic enclave']].map(([title,value,note])=><div className="config-item" key={title}><small>{title}</small><b>{value}</b><span>{note}</span></div>)}</div><div className="config-foot"><span><CheckCircle2 size={15}/> Kernel-bypass DPDK polling active</span><Pill tone="green">0 dropped frames</Pill></div></Card></div>
      <aside className="settings-aside"><Card className="photonic-card"><PanelHeading title="Physical photonic link status" subtitle="Live DDM sensors"/><div className="diag-list"><p><span>Tap #01-RX · Peering trunk</span><b className="value-green">−4.18 dBm</b></p><p><span>Tap #02-RX · Core DMZ</span><b className="value-green">−4.35 dBm</b></p><p><span>Standby optical node</span><b>−26.10 dBm</b></p><p><span>TX optical return vector</span><b className="value-rose">0.00000 µW</b></p></div><div className="status-banner"><ShieldCheck size={15}/>Laser disabled · physically severed</div></Card><Card><div className="settings-panel-title compact-title"><span className="node-icon icon-amber"><LockKeyhole size={17}/></span><span><h2>Air-gapped threat intel staging</h2><p>Signed offline release policy</p></span></div><small className="fingerprint-label">ED25519 RELEASE KEY FINGERPRINT</small><code className="fingerprint">SHA256:4A91B872F0C85B229A109E94A7312C208BF208B8710325D34C7A1D20E82DB64A</code><SettingCheck checked={policy} onChange={()=>setPolicy(!policy)}>Auto-quarantine unsigned CTI feeds</SettingCheck><SettingCheck checked={true} onChange={()=>toast('Model-weight signature validation is required.')}>Validate model weights before deploy</SettingCheck><Button variant="dark" icon={LockKeyhole} className="full-width" onClick={()=>toast('Offline one-way ingest is ready for signed staging.')}>Initiate offline one-way ingest</Button></Card></aside></div>
  </>;
}

function Switch({ checked, onChange, label }) { return <button role="switch" aria-checked={checked} aria-label={label} className={`switch ${checked?'switch-on':''}`} onClick={onChange}><i/></button>; }
function SettingRow({ title, description, status, children }) { return <div className="setting-row"><div><b>{title}</b><p>{description}</p>{status&&<small className="value-green">{status}</small>}</div><div className="setting-control">{children}</div></div>; }
function SettingCheck({ checked, onChange, children }) { return <label className="setting-check"><input type="checkbox" checked={checked} onChange={onChange}/><span>{children}</span></label>; }

function Modal({ title, onClose, children, className = '' }) { return <div className="modal-backdrop" role="presentation" onClick={onClose}><section className={`modal ${className}`} role="dialog" aria-modal="true" aria-label={title} onClick={(e)=>e.stopPropagation()}><div className="modal-header"><h2>{title}</h2><IconButton aria-label="Close dialog" onClick={onClose}><X size={18}/></IconButton></div>{children}</section></div>; }

function DetectionDetails({ alert, onClose }) {
  const sensor = alert.sensor || {};
  return <Modal title="Detection details" onClose={onClose} className="detection-modal">
    <div className="detection-detail-heading"><Pill tone={alert.severity.toLowerCase()}>{alert.severity}</Pill><span className="mono muted">{alert.id}</span></div>
    <h3 className="detection-detail-title">{alert.title}</h3>
    <p className="detection-description">{alert.description}</p>
    <section className="detection-detail-section"><h4>Overall assessment</h4><p>{alert.conclusion}</p></section>
    <section className="detection-detail-section"><h4>Recommended preventive measures</h4><ul className="detection-measures">{alert.preventiveMeasures.map((measure) => <li key={measure}>{measure}</li>)}</ul></section>
    <div className="detection-facts">
      <div><span>Source</span><b>{alert.src}</b></div><div><span>Destination</span><b>{alert.dst}</b></div>
      <div><span>Protocol</span><b>{alert.proto}</b></div><div><span>Confidence</span><b>{alert.confidence}</b></div>
      <div><span>Severity</span><b>{alert.severity}</b></div><div><span>Inference latency</span><b>{alert.latencyMs.toFixed(2)} ms</b></div>
      <div><span>Detected (UTC)</span><b>{alert.time}</b></div>
    </div>
    <section className="detection-detail-section"><h4>Model results</h4>
      {alert.modelResults.length ? <div className="detection-model-list">{alert.modelResults.map((model, index) => <div key={`${model.name}-${index}`}><b>{model.name}</b><span>{model.label || 'No label'} · {(model.score * 100).toFixed(1)}%</span></div>)}</div> : <p>No model score details were returned for this alert.</p>}
    </section>
    <section className="detection-detail-section"><h4>Sensor context</h4>
      {sensor.sensor || sensor.feature_profile || sensor.termination
        ? <div className="detection-context"><span>Sensor: {sensor.sensor || 'Not provided'}</span><span>Feature profile: {sensor.feature_profile || 'Not provided'}</span><span>Flow end: {sensor.termination || 'Not provided'}</span><span>Observation: {sensor.flow_direction || alert.proto}</span></div>
        : <p>No additional sensor context was returned.</p>}
    </section>
    {alert.rulesFired.length > 0 && <section className="detection-detail-section"><h4>Rules fired</h4><p>{alert.rulesFired.join(', ')}</p></section>}
    {alert.mitre.length > 0 && <section className="detection-detail-section"><h4>MITRE ATT&amp;CK references</h4><p>{alert.mitre.map((item) => `${item.id} ${item.name}`).join(' · ')}</p></section>}
  </Modal>;
}

export default function App() {
  const [live, setLive] = useState({ alerts: [], totalAlerts: 0, totalDetections: 0, flowsPerSecond: 0, models: [], batchSummary: null, connected: false });
  useEffect(() => {
    let disposed = false;
    const refresh = async () => {
      try {
        const [alertsResponse, metricsResponse, modelsResponse] = await Promise.all(['/api/alerts?limit=500', '/api/metrics', '/api/models'].map((url) => fetch(url, { headers: { 'x-uniguard-dashboard': '1' } })));
        if (![alertsResponse, metricsResponse, modelsResponse].every((response) => response.ok)) throw new Error('Backend API unavailable');
        const [alertsData, metricsData, modelsData] = await Promise.all([alertsResponse.json(), metricsResponse.json(), modelsResponse.json()]);
        if (!disposed) setLive({ alerts: (alertsData.alerts || []).map(mapAlert), totalAlerts: alertsData.total || 0, totalDetections: metricsData.total_detections || 0, batchSummary: alertsData.latest_batch_summary || null, flowsPerSecond: metricsData.flows_per_sec || 0, models: (modelsData || []).flatMap((model) => {
          const expandedModels = model.name === 'lgbm_iforest'
            ? [{ ...model, name: 'lightgbm', display_name: 'LightGBM Flow Classifier' }, { ...model, name: 'iforest', display_name: 'Isolation Forest Anomaly Detector', precision: null, recall: null }]
            : [model]
          return expandedModels.map((model) => {
          const modelDetails = {
            beacon_cnn: ['Beacon 1D-CNN', 'CNN', 'FFT and packet timing patterns for beacon and botnet detection', 'Packet sizes, inter-arrival timing, TCP flags'],
            charcnn_dns: ['Char-CNN DNS Detector', 'NLP', 'Character and lexical analysis for DNS threat detection', 'Domain entropy, character n-grams, label lengths'],
            lightgbm: ['LightGBM Flow Classifier', 'ML', 'Supervised classification of observed network flow features', 'Flow duration, forward packet counts, byte and timing statistics'],
            iforest: ['Isolation Forest', 'ML', 'Unsupervised anomaly scoring for unusual network flows', 'Flow feature outlier scores'],
          }[model.name] || [model.display_name || model.name, 'ML', 'Backend model registry health', '']
          const percent = value => value == null ? 'N/A' : `${(Number(value) * 100).toFixed(1)}%`
          const bytes = Number(model.footprint_bytes || 0)
          return { name: modelDetails[0], type: modelDetails[1], description: modelDetails[2], features: modelDetails[3], version: model.version, status: model.status,
            latency: model.latency_ms == null ? 'Awaiting inference' : `${Number(model.latency_ms).toFixed(2)} ms`, latencyPercentile: model.latency_percentile,
            memory: bytes ? (bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`) : 'N/A',
            drift: model.drift_psi != null ? Number(model.drift_psi).toFixed(3) : `${model.drift_status === 'collecting_comparison' ? 'Compare' : 'Baseline'} ${Number(model.drift_samples || 0)}/${Number(model.drift_window_size || 50)}`,
            precision: percent(model.precision), recall: percent(model.recall),
            inferenceCount: Number(model.inference_count || 0), color: modelDetails[1] === 'CNN' ? 'purple' : modelDetails[1] === 'NLP' ? 'green' : 'blue' }
          })
        }), connected: true });
      } catch { if (!disposed) setLive((current) => ({ ...current, connected: false })); }
    };
    void refresh(); const timer = window.setInterval(refresh, 500);
    return () => { disposed = true; window.clearInterval(timer); };
  }, []);
  const routeForPath = () => {
    const segment = window.location.pathname.replace(/^\/+|\/+$/g, '');
    return navItems.some((item) => item.id === segment) ? segment : 'overview';
  };
  const [route, setRoute] = useState(routeForPath);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notice, setNotice] = useState('');
  const navigate = (nextRoute) => {
    const nextPath = nextRoute === 'overview' ? '/' : `/${nextRoute}`;
    if (window.location.pathname !== nextPath) window.history.pushState({}, '', nextPath);
    setRoute(nextRoute);
  };
  useEffect(() => {
    const onPopState = () => setRoute(routeForPath());
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);
  const current = navItems.find((item)=>item.id===route) ?? navItems[0];
  const toast = (message) => { setNotice(message); window.clearTimeout(window.__uniguardToast); window.__uniguardToast = window.setTimeout(()=>setNotice(''), 3200); };
  const view = useMemo(() => {
    switch (route) {
      case 'alerts': return <Alerts toast={toast}/>;
      case 'hosts': return <Hosts toast={toast}/>;
      case 'models': return <Models toast={toast}/>;
      case 'hunting': return <Hunting toast={toast}/>;
      case 'settings': return <Settings toast={toast}/>;
      default: return <Overview onNavigate={navigate} toast={toast}/>;
    }
  }, [route]);
  return <LiveDataContext.Provider value={live}><div className="app-shell"><Sidebar current={route} onNavigate={navigate} mobileOpen={mobileOpen} setMobileOpen={setMobileOpen}/><div className="app-main"><TopBar onMenu={()=>setMobileOpen(true)} toast={toast}/><main className="page-content"><div className="page-inner"><div className="mobile-page-label"><span>{current.label}</span><ChevronDown size={14}/></div>{view}<footer className="page-footer"><span>UNIGUARD · PASSIVE THREAT INTELLIGENCE</span><span><i/>{live.connected ? 'Backend connected; live data' : 'Backend unavailable; reconnecting'}</span></footer></div></main></div>{notice&&<div role="status" className="toast"><CheckCircle2 size={17}/>{notice}<button aria-label="Dismiss notification" onClick={()=>setNotice('')}><X size={15}/></button></div>}</div></LiveDataContext.Provider>;
}
