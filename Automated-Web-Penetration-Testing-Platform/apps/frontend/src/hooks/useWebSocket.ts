import { useEffect, useRef, useState } from 'react'
import { WS_BASE } from '../services/api'

export interface UseWebSocketOptions {
  onMessage?: (data: unknown) => void
  reconnect?: boolean
  reconnectDelayMs?: number
}

export function useWebSocket(path: string | null, opts: UseWebSocketOptions = {}) {
  const { onMessage, reconnect = true, reconnectDelayMs = 2000 } = opts
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!path) return
    let cancelled = false

    const open = () => {
      const ws = new WebSocket(`${WS_BASE}${path}`)
      wsRef.current = ws
      ws.onopen = () => setConnected(true)
      ws.onclose = () => {
        setConnected(false)
        wsRef.current = null
        if (!cancelled && reconnect) {
          timerRef.current = setTimeout(open, reconnectDelayMs)
        }
      }
      ws.onmessage = (e) => {
        try {
          onMessage?.(JSON.parse(e.data))
        } catch {
          onMessage?.(e.data)
        }
      }
    }

    open()
    return () => {
      cancelled = true
      if (timerRef.current) clearTimeout(timerRef.current)
      wsRef.current?.close()
    }
  }, [path, reconnect, reconnectDelayMs, onMessage])

  const send = (data: unknown) => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? data : JSON.stringify(data))
    }
  }

  return { connected, send }
}
