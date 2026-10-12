import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { useStore } from "../store/useStore"

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#ff2d55", HIGH: "#ff6b00", MEDIUM: "#ffd60a", LOW: "#0af0ff", INFO: "#4a5568"
}

export default function Alerts() {
  const alerts = useStore(s => s.alerts)
  const [selected, setSelected] = useState<(typeof alerts)[0] | null>(null)
  const [filter, setFilter] = useState("")

  const filtered = filter
    ? alerts.filter(a => a.threat_class.includes(filter.toUpperCase()) || a.five_tuple.src_ip.includes(filter) || a.severity === filter.toUpperCase())
    : alerts

  return (
    <div className="flex h-full w-full overflow-hidden">
      {/* Main Table */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="pane-header shrink-0" style={{ background: "#060810", borderBottom: "1px solid rgba(0,255,136,0.15)" }}>
          <div className="flex items-center gap-3">
            <span>LIVE DETECTIONS</span>
            <motion.span
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ duration: 1.5, repeat: Infinity }}
              style={{ color: "#00ff88", fontSize: 9 }}>
              ● {alerts.length} EVENTS
            </motion.span>
          </div>
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="/ filter..."
            className="text-[10px] px-2 py-0.5 bg-transparent outline-none"
            style={{ border: "1px solid #1a2236", color: "#c8d6f0", width: 150, fontFamily: "monospace" }}
          />
        </div>

        {/* Table header */}
        <div className="shrink-0 table-row text-[9px] tracking-[0.15em] uppercase sticky top-0 z-10"
          style={{ background: "#060810", color: "#4a5568", borderBottom: "1px solid rgba(0,255,136,0.1)", height: 24 }}>
          <div className="w-24">TIME</div>
          <div className="w-28">SEV</div>
          <div className="w-40">CLASS</div>
          <div className="w-32">SRC</div>
          <div className="w-8 text-center">▶</div>
          <div className="w-32">DST</div>
          <div className="w-16">CONF</div>
          <div className="flex-1">MITRE</div>
        </div>

        <div className="flex-1 overflow-y-auto" style={{ background: "#060810" }}>
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <motion.div animate={{ opacity: [1, 0.3, 1] }} transition={{ duration: 1.5, repeat: Infinity }} style={{ color: "#4a5568", fontSize: 11 }}>
                AWAITING STREAM DATA...
              </motion.div>
            </div>
          ) : (
            filtered.map((a, i) => {
              const col = SEV_COLOR[a.severity] || "#4a5568"
              const isActive = selected?.alert_id === a.alert_id
              return (
                <motion.div
                  key={a.alert_id || i}
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.12, delay: Math.min(i * 0.01, 0.3) }}
                  onClick={() => setSelected(isActive ? null : a)}
                  className="table-row relative"
                  style={{ background: isActive ? `${col}10` : undefined, borderLeft: `2px solid ${isActive ? col : "transparent"}` }}>
                  <div className="w-24 text-[10px]" style={{ color: "#2d3748", fontFamily: "monospace" }}>
                    {new Date(a.timestamp).toISOString().split("T")[1].slice(0, 8)}
                  </div>
                  <div className="w-28 flex items-center gap-1.5 text-[10px]">
                    <div className="w-1.5 h-1.5 rounded-full" style={{ background: col, boxShadow: `0 0 6px ${col}` }} />
                    <span style={{ color: col, textShadow: a.severity === "CRITICAL" ? `0 0 8px ${col}` : "none" }}>{a.severity}</span>
                  </div>
                  <div className="w-40 text-[11px] font-bold truncate" style={{ color: col }}>{a.threat_class}</div>
                  <div className="w-32 text-[10px] truncate" style={{ color: "#4a5568", fontFamily: "monospace" }}>{a.five_tuple.src_ip}</div>
                  <div className="w-8 text-center text-[10px]" style={{ color: "#1a2236" }}>{">"}</div>
                  <div className="w-32 text-[10px] truncate" style={{ color: "#4a5568", fontFamily: "monospace" }}>{a.five_tuple.dst_ip}</div>
                  <div className="w-16 text-[10px]" style={{ color: "#c8d6f0" }}>{(a.confidence * 100).toFixed(0)}%</div>
                  <div className="flex-1 text-[10px] truncate" style={{ color: "#4a5568" }}>{a.mitre_technique || "—"}</div>
                </motion.div>
              )
            })
          )}
        </div>
      </div>

      {/* Inspection Drawer */}
      <AnimatePresence>
        {selected && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 360, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
            className="shrink-0 flex flex-col overflow-hidden"
            style={{ borderLeft: "1px solid rgba(0,255,136,0.2)", background: "#0b0f1a" }}>
            <div className="pane-header">
              <span>INSPECTION</span>
              <button onClick={() => setSelected(null)} style={{ color: "#4a5568" }} className="hover:text-white transition-colors">✕</button>
            </div>
            <div className="p-3 flex-1 overflow-y-auto space-y-4 text-[11px]">
              {/* Alert ID */}
              <div>
                <div className="text-[9px] tracking-[0.15em] uppercase mb-1" style={{ color: "#4a5568" }}>Alert ID</div>
                <div style={{ color: "#00d4ff", fontFamily: "monospace", fontSize: 10 }}>{selected.alert_id}</div>
              </div>

              {/* Severity */}
              <div className="flex items-center gap-2 p-2" style={{ border: `1px solid ${SEV_COLOR[selected.severity]}40`, background: `${SEV_COLOR[selected.severity]}08` }}>
                <div className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[selected.severity], boxShadow: `0 0 8px ${SEV_COLOR[selected.severity]}` }} />
                <span style={{ color: SEV_COLOR[selected.severity], fontWeight: 700, fontSize: 12 }}>{selected.severity}</span>
                <span style={{ color: "#4a5568" }}>— {selected.threat_class}</span>
              </div>

              {/* Flow */}
              <div>
                <div className="text-[9px] tracking-[0.15em] uppercase mb-2" style={{ color: "#4a5568" }}>Network Flow</div>
                <div className="flex items-center gap-2" style={{ fontFamily: "monospace", fontSize: 10 }}>
                  <div className="px-2 py-1" style={{ border: "1px solid #1a2236", color: "#c8d6f0" }}>
                    {selected.five_tuple.src_ip}:{selected.five_tuple.src_port}
                  </div>
                  <span style={{ color: "#00ff88" }}>{"═══▶"}</span>
                  <div className="px-2 py-1" style={{ border: "1px solid #1a2236", color: "#c8d6f0" }}>
                    {selected.five_tuple.dst_ip}:{selected.five_tuple.dst_port}
                  </div>
                </div>
                <div className="mt-1" style={{ color: "#4a5568", fontSize: 10 }}>TCP/{selected.five_tuple.proto}</div>
              </div>

              {/* Confidence */}
              <div>
                <div className="text-[9px] tracking-[0.15em] uppercase mb-1" style={{ color: "#4a5568" }}>Ensemble Confidence</div>
                <div className="relative h-2 w-full" style={{ background: "#1a2236" }}>
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${selected.confidence * 100}%` }}
                    transition={{ duration: 0.6, ease: "easeOut" }}
                    className="absolute inset-y-0 left-0"
                    style={{ background: `linear-gradient(90deg, ${SEV_COLOR[selected.severity]}, ${SEV_COLOR[selected.severity]}88)` }} />
                </div>
                <div className="mt-1 text-right" style={{ color: "#c8d6f0", fontSize: 10 }}>{(selected.confidence * 100).toFixed(1)}%</div>
              </div>

              {/* Raw JSON */}
              <div>
                <div className="text-[9px] tracking-[0.15em] uppercase mb-1" style={{ color: "#4a5568" }}>Raw Telemetry</div>
                <pre className="text-[10px] p-2 overflow-x-auto" style={{ background: "#060810", border: "1px solid #1a2236", color: "#4a5568", fontFamily: "monospace" }}>
                  {JSON.stringify(selected, null, 2)}
                </pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
