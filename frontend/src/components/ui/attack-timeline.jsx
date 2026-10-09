import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const COLORS = ['#e64970', '#8b5cf6', '#0ea5a4', '#f59e0b', '#3b82f6', '#ec4899', '#64748b'];

function CurvedLine({ points = [], stroke, strokeWidth }) {
  if (!points.length) return null;
  const [first, ...rest] = points;
  const path = rest.reduce((d, point, index) => {
    const previous = index === 0 ? first : rest[index - 1];
    const dx = point.x - previous.x;
    const handle = dx / 3;
    return `${d} C ${previous.x + handle},${previous.y} ${point.x - handle},${point.y} ${point.x},${point.y}`;
  }, `M ${first.x},${first.y}`);
  return <path d={path} fill="none" stroke={stroke} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />;
}

const timeLabel = (value, span) => new Date(value).toLocaleTimeString([], {
  timeZone: 'UTC', hour: '2-digit', minute: '2-digit', ...(span < 60_000 ? { second: '2-digit' } : {}), hour12: false,
});

export default function AttackTimeline({ alerts = [] }) {
  const points = alerts
    .map((alert) => ({
      ...alert,
      detectedAt: Date.parse(alert.timestamp),
      category: alert.title || alert.threatClass || 'Unknown threat',
    }))
    .filter((alert) => Number.isFinite(alert.detectedAt))
    .sort((a, b) => a.detectedAt - b.detectedAt);

  if (!points.length) {
    return <div className="chart-empty"><strong>No detections in the feed</strong><span>Attack markers will appear at the timestamps reported by the backend.</span></div>;
  }

  const first = points[0].detectedAt;
  const last = points[points.length - 1].detectedAt;
  const span = last - first;
  const bucketMs = span < 60_000 ? 1_000 : span < 3_600_000 ? 10_000 : 60_000;
  const categories = [...new Set(points.map((point) => point.category))];
  const grouped = new Map();
  for (const point of points) {
    const time = Math.floor(point.detectedAt / bucketMs) * bucketMs;
    const row = grouped.get(time) || { time };
    row[point.category] = (row[point.category] || 0) + 1;
    grouped.set(time, row);
  }
  const data = [...grouped.values()].sort((a, b) => a.time - b.time);
  const domain = [data[0].time - bucketMs / 2, data[data.length - 1].time + bucketMs / 2];
  for (const row of data) {
    for (const category of categories) row[category] ??= null;
  }
  const colors = Object.fromEntries(categories.map((category, index) => [category, COLORS[index % COLORS.length]]));

  return <div style={{ width: '100%', height: '100%', minHeight: 240 }}>
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 16, right: 22, bottom: 12, left: 4 }}>
        <CartesianGrid stroke="var(--border, #273244)" strokeDasharray="3 5" vertical={false} />
        <XAxis dataKey="time" type="number" scale="time" domain={domain} name="Detected at"
          tickFormatter={(value) => timeLabel(value, span)} tickCount={6} minTickGap={44} interval="preserveStartEnd"
          tick={{ fill: 'var(--muted-foreground, #98a6b9)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fill: 'var(--muted-foreground, #98a6b9)', fontSize: 11 }}
          axisLine={false} tickLine={false} width={42} />
        <Tooltip cursor={{ fill: 'rgba(148, 163, 184, 0.10)' }}
          labelFormatter={(value) => new Date(value).toLocaleString([], { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'medium', hour12: false })}
          formatter={(value, name) => [value, name]}
          contentStyle={{ background: 'var(--card, #111827)', border: '1px solid var(--border, #273244)', borderRadius: 8 }} />
        {categories.map((category) => <Line key={category} dataKey={category} name={category} type="linear" shape={<CurvedLine />}
          stroke={colors[category]} strokeWidth={2} dot={{ r: 3, strokeWidth: 1 }} activeDot={{ r: 5 }} connectNulls={false} />)}
      </LineChart>
    </ResponsiveContainer>
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 16px', padding: '0 12px', color: 'var(--muted-foreground, #98a6b9)', fontSize: 11 }}>
      {categories.map((category) => <span key={category}><i style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: colors[category], marginRight: 7 }} />{category}</span>)}
      <span style={{ marginLeft: 'auto' }}>{points.length} detection{points.length === 1 ? '' : 's'} · counts by {bucketMs >= 60_000 ? 'minute' : bucketMs >= 10_000 ? '10 seconds' : 'second'}</span>
    </div>
  </div>;
}
