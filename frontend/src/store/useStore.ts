import { create } from 'zustand'

export interface Alert {
  alert_id: string
  timestamp: string
  detected_at: string
  five_tuple: { src_ip: string, dst_ip: string, src_port: number, dst_port: number, proto: string }
  threat_class: string
  severity: string
  confidence: number
  latency_ms: number
  mitre_technique?: string
  explanation?: string
  evidence?: Record<string, unknown>
}

export interface PipelineMetrics {
  timestamp: string
  flows_per_sec: number
  target_flows_per_sec: number
  p95_latency_ms: number
  processing_latency_ms?: number
  measurement_window_seconds?: number
  alerts_per_min: number
  dropped_records: number
  models: { name: string; status: string; version: string; inference_count?: number; p50_ms?: number; p95_ms?: number; p99_ms?: number; footprint_bytes?: number; drift_psi?: number | null; precision?: number | null; recall?: number | null }[]
}

interface AppState {
  alerts: Alert[]
  totalAlerts: number
  totalDetections: number
  metrics: PipelineMetrics | null
  flowsPerSecond: number
  measurementWindowSeconds: number
  isConnected: boolean
  addAlert: (alert: Alert) => void
  setRecentAlerts: (alerts: Alert[], total: number) => void
  setMetrics: (metrics: PipelineMetrics) => void
  setThroughput: (flowsPerSecond: number, measurementWindowSeconds: number, totalDetections?: number, totalAlerts?: number) => void
  setIsConnected: (status: boolean) => void
}

export const useStore = create<AppState>((set) => ({
  alerts: [],
  totalAlerts: 0,
  totalDetections: 0,
  metrics: null,
  flowsPerSecond: 0,
  measurementWindowSeconds: 3,
  isConnected: false,
  
  addAlert: (alert) => set((state) => {
    if (state.alerts.some(existing => existing.alert_id === alert.alert_id)) return state
    return {
      alerts: [alert, ...state.alerts].slice(0, 100),
      totalAlerts: state.totalAlerts + 1,
    }
  }),

  setRecentAlerts: (incoming, total) => set((state) => {
    // The backend's in-memory total returns to zero when its alert history is reset.
    // Replace the local cache on that drop so polling cannot keep old alerts visible.
    if (total < state.totalAlerts) {
      return { alerts: incoming.slice(0, 100), totalAlerts: total }
    }
    const byId = new Map<string, Alert>()
    for (const alert of [...state.alerts, ...incoming]) byId.set(alert.alert_id, alert)
    const alerts = [...byId.values()]
      .sort((a, b) => Date.parse(b.detected_at || b.timestamp) - Date.parse(a.detected_at || a.timestamp))
      .slice(0, 100)
    return { alerts, totalAlerts: Math.max(total, state.totalAlerts, alerts.length) }
  }),
  
  setMetrics: (metrics) => set({ metrics }),
  setThroughput: (flowsPerSecond, measurementWindowSeconds, totalDetections, totalAlerts) => set((state) => ({
    flowsPerSecond,
    measurementWindowSeconds,
    ...(totalDetections != null ? { totalDetections } : {}),
    ...(totalAlerts != null ? { totalAlerts: Math.max(totalAlerts, state.totalAlerts) } : {}),
  })),
  setIsConnected: (status) => set({ isConnected: status }),
}))
