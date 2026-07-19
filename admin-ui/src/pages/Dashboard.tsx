import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { AdminStats } from '../api/types'
import { StatusPill, formatBytes, formatWhen, shortId } from '../components/format'

export function Dashboard() {
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .stats(8)
      .then(setStats)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Lab overview</h1>
          <p>Live inventory of owned test devices, research jobs, and captures.</p>
        </div>
        <div className="toolbar">
          <button type="button" className="btn" onClick={load} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="hero-strip">
        <div className="hero-brand">
          <div className="eyebrow">normalcf console</div>
          <h2>Watch the lab, not the wild.</h2>
          <p>
            Operator view for defensive research — device presence, job queues, and
            artifact indexes on D1.
          </p>
        </div>
        <div className="metric-grid">
          <div className="metric">
            <div className="label">Devices</div>
            <div className="value">{stats?.total_devices ?? '—'}</div>
          </div>
          <div className="metric">
            <div className="label">Online</div>
            <div className="value">{stats?.online_devices ?? '—'}</div>
          </div>
          <div className="metric">
            <div className="label">Pending jobs</div>
            <div className="value">{stats?.pending_jobs ?? '—'}</div>
          </div>
          <div className="metric">
            <div className="label">Artifacts</div>
            <div className="value">{stats?.total_artifacts ?? '—'}</div>
          </div>
        </div>
      </div>

      <div className="metric-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="metric">
          <div className="label">Running</div>
          <div className="value">{stats?.running_jobs ?? '—'}</div>
        </div>
        <div className="metric">
          <div className="label">Completed</div>
          <div className="value">{stats?.completed_jobs ?? '—'}</div>
        </div>
        <div className="metric">
          <div className="label">Failed</div>
          <div className="value">{stats?.failed_jobs ?? '—'}</div>
        </div>
        <div className="metric">
          <div className="label">Artifact bytes</div>
          <div className="value" style={{ fontSize: '1.25rem' }}>
            {formatBytes(stats?.total_artifact_bytes)}
          </div>
        </div>
      </div>

      <section className="panel">
        <h3>Recent devices</h3>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>UUID</th>
                <th>Model</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recent_devices ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4} className="empty">
                    No devices yet
                  </td>
                </tr>
              ) : (
                stats!.recent_devices.map((d) => (
                  <tr key={d.id}>
                    <td className="mono">
                      <Link to={`/devices/${d.device_uuid}`}>
                        {shortId(d.device_uuid, 14)}
                      </Link>
                    </td>
                    <td>{d.device_model ?? d.device_name ?? '—'}</td>
                    <td>
                      <StatusPill status={d.status} />
                    </td>
                    <td className="muted mono">{formatWhen(d.last_seen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h3>Recent jobs</h3>
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Device</th>
                <th>Status</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {(stats?.recent_jobs ?? []).length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    No jobs yet
                  </td>
                </tr>
              ) : (
                stats!.recent_jobs.map((j) => (
                  <tr key={j.id}>
                    <td className="mono">{j.id}</td>
                    <td>{j.job_type}</td>
                    <td className="mono">{shortId(j.device_uuid)}</td>
                    <td>
                      <StatusPill status={j.status} />
                    </td>
                    <td className="muted mono">{formatWhen(j.created_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
