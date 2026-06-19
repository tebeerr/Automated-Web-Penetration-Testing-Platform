import axios from 'axios'

export const API_BASE = import.meta.env.VITE_API_URL || ''
export const WS_BASE =
  import.meta.env.VITE_WS_URL ||
  (typeof window !== 'undefined'
    ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
    : 'ws://localhost:8000')

export const api = axios.create({
  baseURL: `${API_BASE}/api`,
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('sentinel_token')
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})
