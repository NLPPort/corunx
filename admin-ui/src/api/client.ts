import type {
  AdminStats,
  Artifact,
  Device,
  Event,
  Items,
  Job,
} from './types'
import { clearSession, getToken } from '../auth/session'

const BASE = import.meta.env.VITE_API_BASE ?? ''

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? JSON.stringify(body)
    } catch {
      /* ignore */
    }
    if (res.status === 401 && !path.startsWith('/lab/auth/login')) {
      clearSession()
      if (!window.location.pathname.endsWith('/login')) {
        const base = import.meta.env.BASE_URL.replace(/\/$/, '')
        window.location.assign(`${base}/login`)
      }
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`)
  }
  return res.json() as Promise<T>
}

function qs(params: Record<string, string | number | undefined | null>) {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; expires_at: number; username: string }>(
      '/lab/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      },
    ),

  me: () =>
    request<{ username: string; expires_at: number }>('/lab/auth/me'),

  stats: (recent = 10) =>
    request<AdminStats>(`/lab/admin/stats${qs({ recent })}`),

  listDevices: (opts?: { limit?: number; status?: string }) =>
    request<Items<Device>>(`/lab/devices${qs(opts ?? {})}`),

  getDevice: (uuid: string) =>
    request<{ item: Device }>(`/lab/devices/${encodeURIComponent(uuid)}`),

  patchDevice: (uuid: string, body: Partial<Device>) =>
    request<{ item: Device }>(`/lab/devices/${encodeURIComponent(uuid)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  listJobs: (opts?: { limit?: number; status?: string; device_uuid?: string }) =>
    request<Items<Job>>(`/lab/jobs${qs(opts ?? {})}`),

  createJob: (body: {
    device_uuid?: string
    job_type: string
    payload?: string
    priority?: number
    timeout_seconds?: number
    job_metadata?: string
  }) =>
    request<{ item: Job }>('/lab/jobs', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  listArtifacts: (opts?: {
    limit?: number
    device_uuid?: string
    category?: string
  }) => request<Items<Artifact>>(`/lab/artifacts${qs(opts ?? {})}`),

  listEvents: (opts?: {
    limit?: number
    device_uuid?: string
    event_type?: string
  }) => request<Items<Event>>(`/lab/events${qs(opts ?? {})}`),

  health: () => request<{ status: string; db?: string }>('/health'),
}
