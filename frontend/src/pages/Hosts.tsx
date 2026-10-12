import { useMemo } from 'react'
import { useStore } from '../store/useStore'

export default function Hosts() {
  const alerts = useStore(state => state.alerts)

  const topHosts = useMemo(() => {
    const counts: Record<string, { count: number, maxSev: number, host: string }> = {}
    alerts.forEach(a => {
      const ip = a.five_tuple.src_ip
      if (!counts[ip]) counts[ip] = { count: 0, maxSev: 0, host: `srv-${ip.replace(/\./g, '-')}.local` }
      counts[ip].count++
      const sevMap: Record<string, number> = { 'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25, 'INFO': 10 }
      counts[ip].maxSev = Math.max(counts[ip].maxSev, sevMap[a.severity] || 0)
    })
    return Object.entries(counts)
      .sort((a, b) => b[1].count - a[1].count)
      .map(([ip, data]) => {
        const blocks = Math.round(data.maxSev / 10)
        return {
          ip,
          name: data.host,
          risk: data.maxSev,
          block: '█'.repeat(blocks) + '░'.repeat(10 - blocks),
          alerts: data.count
        }
      })
  }, [alerts])

  return (
    <div className="p-4 flex flex-col h-full space-y-4">
      <div className="pane-header">[ MONITORED ASSETS ]</div>
      
      <div className="pane flex-1 flex flex-col">
        <div className="table-row text-dim uppercase text-[10px] tracking-wider border-b border-border bg-panel">
          <div className="w-32">IP ADDRESS</div>
          <div className="w-48">HOSTNAME</div>
          <div className="w-24 text-right">RISK SCORE</div>
          <div className="flex-1 px-4">RECENT ALERTS</div>
        </div>
        
        <div className="flex-1 overflow-y-auto bg-base text-xs">
          {topHosts.length === 0 ? (
            <div className="p-4 text-dim text-center mt-10">Waiting for stream...</div>
          ) : (
            topHosts.map((h, i) => (
              <div key={i} className="table-row">
                <div className="w-32 font-mono text-dim">{h.ip}</div>
                <div className="w-48 truncate">{h.name}</div>
                <div className="w-24 text-right pr-4 font-mono">
                  <span className={h.risk > 90 ? 'text-critical' : h.risk > 70 ? 'text-high' : 'text-medium'}>
                    {h.block}
                  </span>
                </div>
                <div className="flex-1 px-4 text-dim font-mono">{h.alerts}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
