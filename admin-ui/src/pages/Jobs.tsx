import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { Job } from '../api/types'
import { StatusPill, formatWhen, shortId } from '../components/format'

export function Jobs() {
  const [items, setItems] = useState<Job[]>([])
  const [status, setStatus] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [deviceUuid, setDeviceUuid] = useState('')
  const [jobType, setJobType] = useState('inventory')
  const [payload, setPayload] = useState('')
  const [priority, setPriority] = useState(0)
  const [creating, setCreating] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listJobs({ limit: 100, status: status || undefined })
      .then((r) => setItems(r.items))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [status])

  useEffect(() => {
    load()
  }, [load])

  async function onCreate(e: FormEvent) {
    e.preventDefault()
    setCreating(true)
    setError(null)
    try {
      await api.createJob({
        device_uuid: deviceUuid || undefined,
        job_type: jobType,
        payload: payload || undefined,
        priority,
      })
      setPayload('')
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setCreating(false)
    }
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Jobs</h1>
          <p>Queue research jobs for lab devices — pending → running → result.</p>
        </div>
        <div className="toolbar">
          <div className="field">
            <label htmlFor="job-status">Status</label>
            <select
              id="job-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="">All</option>
              <option value="pending">pending</option>
              <option value="running">running</option>
              <option value="completed">completed</option>
              <option value="failed">failed</option>
              <option value="cancelled">cancelled</option>
              <option value="timeout">timeout</option>
            </select>
          </div>
          <button type="button" className="btn" onClick={load} disabled={loading}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}

      <form className="form-panel" onSubmit={onCreate}>
        <strong style={{ fontFamily: 'var(--font-display)' }}>Create job</strong>
        <div className="form-row">
          <div className="field">
            <label htmlFor="job-device">Device UUID</label>
            <input
              id="job-device"
              value={deviceUuid}
              onChange={(e) => setDeviceUuid(e.target.value)}
              placeholder="optional"
            />
          </div>
          <div className="field">
            <label htmlFor="job-type">Type</label>
            <input
              id="job-type"
              value={jobType}
              onChange={(e) => setJobType(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label htmlFor="job-priority">Priority</label>
            <input
              id="job-priority"
              type="number"
              value={priority}
              onChange={(e) => setPriority(Number(e.target.value))}
            />
          </div>
        </div>
        <div className="field">
          <label htmlFor="job-payload">Payload</label>
          <textarea
            id="job-payload"
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder='JSON or command text'
          />
        </div>
        <div>
          <button type="submit" className="btn btn-primary" disabled={creating}>
            {creating ? 'Creating…' : 'Enqueue'}
          </button>
        </div>
      </form>

      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>ID</th>
              <th>Type</th>
              <th>Device</th>
              <th>Status</th>
              <th>Priority</th>
              <th>Created</th>
              <th>Completed</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={7} className="empty">
                  {loading ? 'Loading…' : 'No jobs'}
                </td>
              </tr>
            ) : (
              items.map((j) => (
                <tr key={j.id}>
                  <td className="mono">{j.id}</td>
                  <td>{j.job_type}</td>
                  <td className="mono">
                    {j.device_uuid ? (
                      <Link to={`/devices/${j.device_uuid}`}>
                        {shortId(j.device_uuid)}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>
                    <StatusPill status={j.status} />
                  </td>
                  <td className="mono">{j.priority ?? 0}</td>
                  <td className="mono muted">{formatWhen(j.created_at)}</td>
                  <td className="mono muted">{formatWhen(j.completed_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
