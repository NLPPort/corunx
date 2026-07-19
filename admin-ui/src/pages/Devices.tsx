import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { Device } from '../api/types'
import { StatusPill, formatWhen, shortId } from '../components/format'

export function Devices() {
  const [items, setItems] = useState<Device[]>([])
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listDevices({ limit: 100, status: status || undefined })
      .then((r) => setItems(r.items))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [status])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p>Owned lab inventory — presence, defend stage, and last activity.</p>
        </div>
        <div className="toolbar">
          <div className="field">
            <label htmlFor="status">Status</label>
            <select
              id="status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All</option>
              <option value="online">online</option>
              <option value="offline">offline</option>
              <option value="busy">busy</option>
              <option value="error">error</option>
            </select>
          </div>
          <button type="button" className="btn" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}

      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>UUID</th>
              <th>Name / model</th>
              <th>iOS</th>
              <th>Status</th>
              <th>Defend</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty">
                  {loading ? 'Loading…' : 'No devices'}
                </td>
              </tr>
            ) : (
              items.map((d) => (
                <tr key={d.id}>
                  <td className="mono">
                    <Link to={`/devices/${d.device_uuid}`}>
                      {shortId(d.device_uuid, 16)}
                    </Link>
                  </td>
                  <td>
                    {d.device_name ?? d.device_model ?? '—'}
                    {d.device_name && d.device_model ? (
                      <div className="muted" style={{ fontSize: '0.8rem' }}>
                        {d.device_model}
                      </div>
                    ) : null}
                  </td>
                  <td className="mono">{d.ios_version ?? '—'}</td>
                  <td>
                    <StatusPill status={d.status} />
                  </td>
                  <td className="mono muted">{d.defend_stage ?? '—'}</td>
                  <td className="mono muted">{formatWhen(d.last_seen)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
