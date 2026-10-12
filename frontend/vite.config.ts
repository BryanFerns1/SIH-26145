import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { randomUUID } from 'node:crypto'
import path from "path"
import { defineConfig, loadEnv } from 'vite'

function requestTelemetry(env: Record<string, string>) {
  return {
    name: 'uniguard-http-request-telemetry',
    configureServer(server: import('vite').ViteDevServer) {
      let observed = 0
      let flushing = false
      const sourceId = randomUUID()
      const backendUrl = process.env.UNIGUARD_BACKEND_URL || env.UNIGUARD_BACKEND_URL || 'http://127.0.0.1:8000'
      const sensorKey = process.env.UNIGUARD_SENSOR_API_KEY || env.UNIGUARD_SENSOR_API_KEY || env.SENSOR_API_KEY
      const sockets = new WeakMap<object, { connection_id: string; client_ip: string; client_port: number; requests_total: number; closed: boolean }>()
      const connections = new Map<string, { connection_id: string; client_ip: string; client_port: number; requests_total: number; closed: boolean }>()
      const reported = new Map<string, { requests_total: number; closed: boolean }>()

      const connectionFor = (request: import('node:http').IncomingMessage) => {
        const socket = request.socket
        const existing = sockets.get(socket)
        if (existing) return existing
        const rawAddress = socket.remoteAddress
        const clientPort = socket.remotePort
        if (!rawAddress || !clientPort) return null
        const connection = {
          connection_id: randomUUID(),
          client_ip: rawAddress.startsWith('::ffff:') ? rawAddress.slice(7) : rawAddress,
          client_port: clientPort,
          requests_total: 0,
          closed: false,
        }
        sockets.set(socket, connection)
        connections.set(connection.connection_id, connection)
        socket.once('close', () => {
          connection.closed = true
          void flush()
        })
        return connection
      }

      server.middlewares.use((request, _response, next) => {
        const method = request.method || 'GET'
        const pathname = new URL(request.url || '/', 'http://vite.local').pathname
        const viteAsset = pathname.startsWith('/@vite/')
          || pathname.startsWith('/@id/')
          || pathname.startsWith('/@fs/')
          || pathname.startsWith('/@react-refresh')
          || pathname.startsWith('/src/')
          || pathname.startsWith('/node_modules/')
          || pathname.startsWith('/assets/')
          || pathname === '/favicon.ico'
          || pathname === '/favicon.svg'
          || pathname === '/vite.svg'
        const websocket = request.headers.upgrade?.toLowerCase() === 'websocket'
        const dashboardPolling = request.headers['x-uniguard-dashboard'] === '1'

        // Count website and application HTTP requests, but exclude Vite's module
        // traffic and the dashboard's own polling so the counter stays useful.
        if (!['HEAD', 'OPTIONS'].includes(method) && !websocket && !dashboardPolling && !viteAsset) {
          const connection = connectionFor(request)
          if (connection) {
            connection.requests_total += 1
            observed += 1
          }
        }
        next()
      })

      const flush = async () => {
        if (flushing) return
        const snapshots = [...connections.values()].filter((connection) => {
          const last = reported.get(connection.connection_id)
          return !last || connection.requests_total > last.requests_total || connection.closed !== last.closed
        }).map((connection) => ({ ...connection }))
        if (!snapshots.length) return
        flushing = true
        try {
          const response = await fetch(`${backendUrl}/api/metrics/http-activity`, {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              ...(sensorKey ? { 'x-sensor-key': sensorKey } : {}),
            },
            body: JSON.stringify({ source_id: sourceId, connections: snapshots }),
          })
          if (response.ok) {
            for (const connection of snapshots) {
              const last = reported.get(connection.connection_id)
              reported.set(connection.connection_id, {
                requests_total: Math.max(last?.requests_total || 0, connection.requests_total),
                closed: connection.closed || Boolean(last?.closed),
              })
              if (connection.closed) {
                connections.delete(connection.connection_id)
                reported.delete(connection.connection_id)
              }
            }
          }
          else console.warn(`[UniGuard] HTTP request telemetry rejected (${response.status})`)
        } catch {
          // Keep the cumulative total pending; idempotent retries cannot double count.
        } finally {
          flushing = false
        }
      }
      const timer = setInterval(() => { void flush() }, 500)
      timer.unref?.()
      server.httpServer?.once('close', () => {
        clearInterval(timer)
        // Try to deliver requests that arrived just before a graceful shutdown.
        void flush()
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  return {
    plugins: [requestTelemetry(env), react(), tailwindcss()],
    resolve: {
      alias: {
        "@": path.resolve(import.meta.dirname, "./src"),
      },
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
        },
        '/ws': {
          target: 'http://127.0.0.1:8000',
          ws: true,
        }
      }
    }
  }
})
