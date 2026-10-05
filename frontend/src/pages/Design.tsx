import { useEffect, useRef } from 'react'
import * as echarts from 'echarts/core'
import { LineChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { registerTheme } from '../lib/echarts-theme'

echarts.use([LineChart, BarChart, GridComponent, TooltipComponent, CanvasRenderer])
registerTheme()

function ChartDemo() {
  const chartRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!chartRef.current) return
    const chart = echarts.init(chartRef.current, 'terminal')
    
    chart.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 30, right: 10, top: 10, bottom: 20 },
      xAxis: {
        type: 'category',
        data: ['10:00', '10:01', '10:02', '10:03', '10:04', '10:05']
      },
      yAxis: { type: 'value' },
      series: [
        {
          data: [150, 230, 224, 218, 135, 147],
          type: 'line',
          step: 'end',
          itemStyle: { color: '#6b7686' }
        },
        {
          data: [0, 0, 50, 80, 10, 0],
          type: 'bar',
          itemStyle: { color: '#ff3b4e' }
        }
      ]
    })

    return () => chart.dispose()
  }, [])

  return <div ref={chartRef} className="w-full h-32" />
}

export default function Design() {
  return (
    <div className="p-8 space-y-8 max-w-4xl">
      <div className="pane">
        <div className="pane-header">Primitives</div>
        <div className="p-4 space-y-4">
          <div className="flex space-x-4">
            <button className="px-3 py-1 bg-border text-text hover:bg-dim hover:text-white transition-none text-xs uppercase font-bold tracking-wider">Default Btn</button>
            <button className="px-3 py-1 bg-accent text-base hover:bg-accent/80 transition-none text-xs uppercase font-bold tracking-wider">Accent Btn</button>
            <input type="text" defaultValue="> filter src_ip=10.0.0.1" className="bg-base border border-border px-2 py-1 text-xs text-text focus:border-dim outline-none w-64" />
          </div>
          
          <div className="flex space-x-4 items-center">
            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 bg-critical/20 text-critical border border-critical/30">CRITICAL</span>
            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 bg-high/20 text-high border border-high/30">HIGH</span>
            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 bg-medium/20 text-medium border border-medium/30">MEDIUM</span>
            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 bg-low/20 text-low border border-low/30">LOW</span>
            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 bg-info/20 text-info border border-info/30">INFO</span>
            <span className="hotkey">Esc</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="pane">
          <div className="pane-header">Stat Cell</div>
          <div className="p-3">
            <div className="text-dim text-[10px] uppercase tracking-wider mb-1">Throughput</div>
            <div className="flex justify-between items-end">
              <div className="text-2xl font-bold leading-none">5,204</div>
              <div className="text-accent text-xs">↑ 12%</div>
            </div>
            <div className="h-8 mt-2 opacity-50 bg-base flex items-end justify-between px-1 gap-[1px]">
               {/* hand-rolled sparkline */}
               {[4, 6, 5, 8, 3, 7, 9, 4, 6, 8].map((h, i) => (
                 <div key={i} className="w-full bg-dim" style={{height: `${h*10}%`}} />
               ))}
            </div>
          </div>
        </div>

        <div className="pane col-span-2">
          <div className="pane-header">Chart Panel</div>
          <div className="p-3 bg-base m-2 border border-border">
            <ChartDemo />
          </div>
        </div>
      </div>

      <div className="pane">
        <div className="pane-header">Data Table <span className="text-dim font-normal normal-case">showing 3 of 402</span></div>
        <div className="bg-base border-t border-border">
          <div className="table-row text-dim uppercase text-[10px] tracking-wider border-b border-border bg-panel">
            <div className="w-24">TIME</div>
            <div className="w-24">SRC</div>
            <div className="w-8 text-center">→</div>
            <div className="w-24">DST</div>
            <div className="w-32">CLASS</div>
            <div className="w-16">CONF</div>
          </div>
          {[
            { t: '14:02:11.482Z', src: '10.2.4.17', dst: '185.12.x.x', c: 'C2_BEACON', conf: 0.93, sev: 'critical' },
            { t: '14:02:11.490Z', src: '192.168.1.5', dst: '8.8.8.8', c: 'BENIGN', conf: 0.99, sev: 'info' },
            { t: '14:02:11.501Z', src: '10.0.5.2', dst: '10.0.5.10', c: 'PORTSCAN', conf: 0.81, sev: 'medium' },
          ].map((r, i) => (
            <div key={i} className={`table-row relative ${r.sev === 'critical' ? 'bg-critical/5 text-critical' : ''}`}>
              {r.sev === 'critical' && <div className="absolute left-0 top-0 bottom-0 w-[2px] bg-critical" />}
              <div className="w-24 truncate">{r.t}</div>
              <div className="w-24 truncate">{r.src}</div>
              <div className="w-8 text-center opacity-50">→</div>
              <div className="w-24 truncate">{r.dst}</div>
              <div className="w-32 truncate">{r.c}</div>
              <div className="w-16 flex items-center">
                <div className="w-1 h-3 mr-2 bg-border relative">
                  <div className="absolute bottom-0 left-0 right-0 bg-dim" style={{height: `${r.conf*100}%`}} />
                </div>
                {(r.conf * 100).toFixed(0)}%
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
