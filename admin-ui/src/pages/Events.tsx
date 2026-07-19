import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { Event } from '../api/types'
import { StatusPill, formatWhen, shortId } from '../components/format'

export function Events() {
  const [items, setItems] = useState<Event[]>([])
  const [eventType, setEventType] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listEvents({ limit: 100, event_type: eventType || undefined })
      .then((r) => setItems(r.items))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [eventType])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Events</h1>
          <p>Operator and honeypot timeline for lab activity.</p>
        </div>
        <div className="toolbar">
          <div className="field">
            <label htmlFor="etype">Event type</label>
            <input
              id="etype"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              placeholder="filter"
            />
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
              <th>When</th>
              <th>Type</th>
              <th>Status</th>
              <th>Level</th>
              <th>Device</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty">
                  {loading ? 'Loading…' : 'No events'}
                </td>
              </tr>
            ) : (
              items.map((ev) => (
                <tr key={ev.id}>
                  <td className="mono muted">{formatWhen(ev.created_at)}</td>
                  <td>{ev.event_type}</td>
                  <td>
                    <StatusPill status={ev.status} />
                  </td>
                  <td className="mono muted">{ev.log_level ?? '—'}</td>
                  <td className="mono">
                    {ev.device_uuid ? (
                      <Link to={`/devices/${ev.device_uuid}`}>
                        {shortId(ev.device_uuid)}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>{ev.message ?? '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
