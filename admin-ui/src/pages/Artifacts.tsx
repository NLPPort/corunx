import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { Artifact } from '../api/types'
import { formatBytes, formatWhen, shortId } from '../components/format'

export function Artifacts() {
  const [items, setItems] = useState<Artifact[]>([])
  const [category, setCategory] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .listArtifacts({ limit: 100, category: category || undefined })
      .then((r) => setItems(r.items))
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [category])

  useEffect(() => {
    load()
  }, [load])

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>Artifacts</h1>
          <p>Owned-test capture index — metadata only (storage_path references).</p>
        </div>
        <div className="toolbar">
          <div className="field">
            <label htmlFor="cat">Category</label>
            <input
              id="cat"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="e.g. screenshot"
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
              <th>ID</th>
              <th>Category</th>
              <th>Device</th>
              <th>Path</th>
              <th>Size</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty">
                  {loading ? 'Loading…' : 'No artifacts'}
                </td>
              </tr>
            ) : (
              items.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.id}</td>
                  <td>{a.category}</td>
                  <td className="mono">
                    {a.device_uuid ? (
                      <Link to={`/devices/${a.device_uuid}`}>
                        {shortId(a.device_uuid)}
                      </Link>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="mono muted">{a.path ?? a.storage_path ?? '—'}</td>
                  <td className="mono">{formatBytes(a.file_size)}</td>
                  <td className="mono muted">{formatWhen(a.created_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
