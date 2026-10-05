import { useStore } from '../store/useStore'

export default function Models() {
  const metrics = useStore(state => state.metrics)
  
  // Fake models if no stream yet
  const models = metrics ? metrics.models : [
    { name: 'lgbm_iforest', version: '1.0.0', status: 'REAL' },
    { name: 'beacon_cnn', version: '1.0.0', status: 'REAL' },
    { name: 'charcnn_dns', version: '5.0.0', status: 'REAL' }
  ]

  return (
    <div className="p-4 flex flex-col h-full space-y-4">
      <div className="pane-header">[ ENSEMBLE REGISTRY ]</div>
      
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 overflow-y-auto pb-8">
        {models.map((m, i) => (
          <div key={i} className="pane flex flex-col min-h-[300px]">
            <div className="pane-header flex justify-between">
              <span className="truncate">{m.name}</span>
              <span className={m.status === 'REAL' ? 'text-accent' : 'text-medium'}>
                {m.status}
              </span>
            </div>
            
            <div className="p-4 space-y-6 flex-1 flex flex-col">
              <div className="grid grid-cols-2 gap-4 text-[10px]">
                <div>
                  <div className="text-dim uppercase tracking-wider mb-1">Version</div>
                  <div className="font-mono">{m.version}</div>
                </div>
                <div>
                  <div className="text-dim uppercase tracking-wider mb-1">Format</div>
                  <div className="font-mono text-dim">ONNX / JOB</div>
                </div>
                <div>
                  <div className="text-dim uppercase tracking-wider mb-1">Live Count</div>
                  <div className="font-mono">824,192</div>
                </div>
                <div>
                  <div className="text-dim uppercase tracking-wider mb-1">P95 Latency</div>
                  <div className="font-mono">{metrics ? metrics.p95_latency_ms.toFixed(1) : "2.4"} ms</div>
                </div>
              </div>
              
              <div className="flex-1">
                <div className="text-dim text-[10px] uppercase tracking-wider mb-2">Confidence Heatmap</div>
                <div className="grid grid-cols-10 grid-rows-4 gap-[1px] h-24 bg-border/20 border border-border p-1">
                  {Array.from({ length: 40 }).map((_, j) => {
                    const intensity = Math.random()
                    return (
                      <div 
                        key={j} 
                        className="w-full h-full"
                        style={{ backgroundColor: `rgba(57, 255, 136, ${intensity})` }}
                      />
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
