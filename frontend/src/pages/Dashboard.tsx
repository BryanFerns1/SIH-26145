import { useMemo, useRef, useEffect } from "react"
import { motion } from "framer-motion"
import { useStore } from "../store/useStore"
import * as echarts from "echarts/core"

// ── Animated Stat Card ────────────────────────────────────────────────────────
function StatCard({ label, value, unit, color, delay = 0 }: { label: string; value: string | number; unit?: string; color: string; delay?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay, duration: 0.4, ease: "easeOut" }}
      whileHover={{ scale: 1.02 }}
      className="relative flex flex-col justify-between p-3 overflow-hidden"
      style={{
        background: "#0b0f1a",
        border: `1px solid ${color}33`,
        boxShadow: `inset 0 0 30px ${color}08, 0 0 0 1px ${color}10`,
        minHeight: 80,
      }}>
      {/* Corner accents */}
      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l" style={{ borderColor: color }} />
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r" style={{ borderColor: color }} />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l" style={{ borderColor: color }} />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r" style={{ borderColor: color }} />

      <div className="text-[9px] tracking-[0.2em] uppercase" style={{ color: "#4a5568" }}>{label}</div>
      <div className="text-2xl font-bold leading-none mt-1" style={{ color, textShadow: `0 0 20px ${color}80` }}>
        {value}
        {unit && <span className="text-[10px] font-normal ml-1" style={{ color: "#4a5568" }}>{unit}</span>}
      </div>
    </motion.div>
  )
}

// ── Mini EChart ───────────────────────────────────────────────────────────────
function EChart({ option }: { option: any }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!ref.current) return
    const chart = echarts.init(ref.current)
    chart.setOption({
      backgroundColor: "transparent",
      textStyle: { fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: "#4a5568" },
      ...option,
    })
    const onResize = () => chart.resize()
    window.addEventListener("resize", onResize)
    return () => { window.removeEventListener("resize", onResize); chart.dispose() }
  }, [option])
  return <div ref={ref} className="w-full h-full" />
}

export default function Dashboard() {
  const metrics = useStore(s => s.metrics)
  const alerts = useStore(s => s.alerts)
  const isConnected = useStore(s => s.isConnected)

  const flows = metrics ? Math.round(metrics.flows_per_sec) : 0
  const p95 = metrics ? metrics.p95_latency_ms.toFixed(1) : "0.0"
  const crits = alerts.filter(a => a.severity === "CRITICAL").length
  const highs = alerts.filter(a => a.severity === "HIGH").length
  const modelCount = metrics?.models.length ?? 0

  const classBreakdown = useMemo(() => {
    const counts: Record<string, number> = {}
    alerts.forEach(a => { counts[a.threat_class] = (counts[a.threat_class] || 0) + 1 })
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8)
    return { keys: sorted.map(s => s[0]), values: sorted.map(s => s[1]) }
  }, [alerts])

  const topTalkers = useMemo(() => {
    const counts: Record<string, { count: number; maxSev: number }> = {}
    alerts.forEach(a => {
      const ip = a.five_tuple.src_ip
      if (!counts[ip]) counts[ip] = { count: 0, maxSev: 0 }
      counts[ip].count++
      const sev: Record<string, number> = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25, INFO: 10 }
      counts[ip].maxSev = Math.max(counts[ip].maxSev, sev[a.severity] || 0)
    })
    return Object.entries(counts)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 8)
      .map(([ip, d]) => ({
        ip, count: d.count, score: d.maxSev,
        bar: "█".repeat(Math.round(d.maxSev / 10)) + "░".repeat(10 - Math.round(d.maxSev / 10)),
      }))
  }, [alerts])

  return (
    <div className="h-full flex flex-col gap-3 p-3 overflow-hidden">
      {/* ── KPI Strip ── */}
      <div className="grid grid-cols-6 gap-3 shrink-0">
        <StatCard label="Throughput" value={flows.toLocaleString()} unit="f/s" color="#00ff88" delay={0} />
        <StatCard label="P95 Latency" value={p95} unit="ms" color="#00d4ff" delay={0.05} />
        <StatCard label="Total Alerts" value={alerts.length} color="#c8d6f0" delay={0.1} />
        <StatCard label="Critical" value={crits} color="#ff2d55" delay={0.15} />
        <StatCard label="High" value={highs} color="#ff6b00" delay={0.2} />
        <StatCard label="Models Active" value={modelCount} color="#00ff88" delay={0.25} />
      </div>

      {/* ── Main Grid ── */}
      <div className="flex-1 grid grid-cols-12 gap-3 min-h-0">

        {/* Chart panel */}
        <motion.div
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
          className="col-span-8 flex flex-col pane-glow overflow-hidden">
          <div className="pane-header">CLASS BREAKDOWN — LIVE</div>
          <div className="flex-1 p-2">
            {classBreakdown.keys.length > 0 ? (
              <EChart option={{
                grid: { left: 120, right: 30, top: 10, bottom: 20 },
                tooltip: {
                  trigger: "axis",
                  backgroundColor: "#0b0f1a",
                  borderColor: "#1a2236",
                  textStyle: { color: "#c8d6f0", fontFamily: '"JetBrains Mono", monospace', fontSize: 11 },
                },
                xAxis: { type: "value", axisLine: { lineStyle: { color: "#1a2236" } }, splitLine: { lineStyle: { color: "#1a2236", type: "dashed" } } },
                yAxis: {
                  type: "category",
                  data: classBreakdown.keys,
                  axisLabel: { color: "#4a5568", fontSize: 10 },
                  axisLine: { lineStyle: { color: "#1a2236" } },
                },
                series: [{
                  type: "bar",
                  data: classBreakdown.values.map((v, i) => ({
                    value: v,
                    itemStyle: { color: i === 0 ? "#ff2d55" : i === 1 ? "#ff6b00" : "#00ff88" }
                  })),
                  barMaxWidth: 18,
                }],
              }} />
            ) : (
              <div className="h-full flex items-center justify-center text-xs" style={{ color: "#4a5568" }}>
                <motion.span animate={{ opacity: [1, 0.3, 1] }} transition={{ duration: 1.5, repeat: Infinity }}>
                  AWAITING STREAM DATA...
                </motion.span>
              </div>
            )}
          </div>
        </motion.div>

        {/* Right Column */}
        <div className="col-span-4 flex flex-col gap-3">
          {/* Top Talkers */}
          <motion.div
            initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.35 }}
            className="pane-glow flex-1 flex flex-col overflow-hidden">
            <div className="pane-header">RISKIEST HOSTS</div>
            <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
              {topTalkers.length === 0 ? (
                <div className="p-4 text-center text-xs" style={{ color: "#4a5568" }}>Waiting...</div>
              ) : topTalkers.map((h, i) => (
                <motion.div
                  key={h.ip}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="flex items-center justify-between text-[11px] px-2 py-1 border-b"
                  style={{ borderColor: "rgba(26,34,54,0.5)" }}>
                  <span style={{ color: "#4a5568", fontFamily: "monospace" }}>{h.ip}</span>
                  <span style={{ color: h.score > 90 ? "#ff2d55" : h.score > 70 ? "#ff6b00" : "#ffd60a", letterSpacing: "0" }}>{h.bar}</span>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Live log tail */}
          <motion.div
            initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.45 }}
            className="pane-glow flex-[2] flex flex-col overflow-hidden">
            <div className="pane-header">
              <span>JOURNALCTL -F</span>
              <motion.span
                animate={{ opacity: isConnected ? [1, 0.4, 1] : 1 }}
                transition={{ duration: 1.2, repeat: Infinity }}
                style={{ color: isConnected ? "#00ff88" : "#ff2d55" }}>
                {isConnected ? "● STREAMING" : "✕ OFFLINE"}
              </motion.span>
            </div>
            <div className="flex-1 overflow-y-auto flex flex-col-reverse p-2 text-[10px]" style={{ background: "rgba(6,8,16,0.6)", fontFamily: "monospace" }}>
              {alerts.slice(0, 100).reverse().map((a, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -4 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.15 }}
                  className="whitespace-nowrap truncate hover:bg-white/5 px-1 py-px">
                  <span style={{ color: "#2d3748" }}>{new Date(a.timestamp).toISOString().split("T")[1].slice(0, 8)}</span>
                  <span style={{ color: "#1a2236" }}> | </span>
                  <span style={{
                    color: a.severity === "CRITICAL" ? "#ff2d55" : a.severity === "HIGH" ? "#ff6b00" : "#ffd60a",
                    textShadow: a.severity === "CRITICAL" ? "0 0 6px #ff2d55" : "none",
                  }}>{a.threat_class.padEnd(14)}</span>
                  <span style={{ color: "#1a2236" }}> | </span>
                  <span style={{ color: "#4a5568" }}>{a.five_tuple.src_ip}</span>
                  <span style={{ color: "#2d3748" }}> {"> "}</span>
                  <span style={{ color: "#4a5568" }}>{a.five_tuple.dst_ip}</span>
                </motion.div>
              ))}
              {alerts.length === 0 && (
                <motion.div animate={{ opacity: [1, 0.3, 1] }} transition={{ duration: 1.5, repeat: Infinity }} style={{ color: "#2d3748" }}>
                  Waiting for stream...
                </motion.div>
              )}
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  )
}
