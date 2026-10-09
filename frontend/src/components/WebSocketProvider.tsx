import { useEffect, type ReactNode } from 'react'
import { useStore } from '../store/useStore'

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '')
const apiUrl = (path: string) => `${apiBaseUrl}${path}`
const websocketUrl = apiBaseUrl
  ? `${apiBaseUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:')}/ws`
  : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const addAlert = useStore(state => state.addAlert)
  const setRecentAlerts = useStore(state => state.setRecentAlerts)
  const setMetrics = useStore(state => state.setMetrics)
  const setThroughput = useStore(state => state.setThroughput)
  const setIsConnected = useStore(state => state.setIsConnected)

  useEffect(() => {
    let disposed = false
    let refreshTimer: number | undefined
    let metricsTimer: number | undefined

    const refreshAlerts = async () => {
      try {
        const response = await fetch(apiUrl('/api/alerts?limit=100'), { headers: { 'x-uniguard-dashboard': '1' } })
        if (!response.ok) throw new Error(`Alert history request failed (${response.status})`)
        const result = await response.json() as { total: number; alerts: import('../store/useStore').Alert[] }
        if (!disposed) setRecentAlerts(result.alerts, result.total)
      } catch (error) {
        console.error('Unable to load UniGuard alert history:', error)
      }
    }

    void refreshAlerts()
    refreshTimer = window.setInterval(refreshAlerts, 3000)

    const refreshThroughput = async () => {
      try {
        const response = await fetch(apiUrl('/api/metrics'), { headers: { 'x-uniguard-dashboard': '1' } })
        if (!response.ok) throw new Error(`Throughput request failed (${response.status})`)
        const result = await response.json() as { flows_per_sec: number; measurement_window_seconds: number; total_detections?: number; total_alerts?: number }
        if (!disposed) setThroughput(result.flows_per_sec, result.measurement_window_seconds, result.total_detections, result.total_alerts)
      } catch (error) {
        if (!disposed) setThroughput(0, 3)
        console.error('Unable to load UniGuard throughput:', error)
      }
    }

    void refreshThroughput()
    metricsTimer = window.setInterval(refreshThroughput, 1000)

    let socket: WebSocket | null = null
    let reconnectTimer: number | undefined
    let retry = 0

    const connect = () => {
      if (disposed) return
      socket = new WebSocket(websocketUrl)

      socket.onopen = () => {
        retry = 0
        setIsConnected(true)
      }
      socket.onmessage = event => {
        try {
          const message = JSON.parse(event.data)
          if (message.type === 'NEW_ALERT' && message.data) addAlert(message.data)
          if (message.type === 'METRICS_UPDATE' && message.data) setMetrics(message.data)
        } catch (error) {
          console.error('Unable to read a UniGuard stream update:', error)
        }
      }
      socket.onclose = () => {
        setIsConnected(false)
        if (!disposed) {
          const delay = Math.min(1000 * 2 ** retry, 15000)
          retry += 1
          reconnectTimer = window.setTimeout(connect, delay)
        }
      }
      socket.onerror = () => socket?.close()
    }

    connect()
    return () => {
      disposed = true
      window.clearTimeout(reconnectTimer)
      window.clearInterval(refreshTimer)
      window.clearInterval(metricsTimer)
      socket?.close()
      setIsConnected(false)
    }
  }, [addAlert, setMetrics, setIsConnected, setRecentAlerts, setThroughput])

  return children
}
