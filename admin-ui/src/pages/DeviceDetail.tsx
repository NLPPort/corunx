import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import type { Device } from '../api/types'
import { StatusPill, formatBytes, formatWhen } from '../components/format'

export function DeviceDetail() {
  const { uuid = '' } = useParams()
  const [device, setDevice] = useState<Device | null>(null)
  const [notes, setNotes] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(() => {
    setError(null)
    api
      .getDevice(uuid)
      .then((r) => {
        setDevice(r.item)
        setNotes(r.item.notes ?? '')
      })
      .catch((e: Error) => setError(e.message))
  }, [uuid])

  useEffect(() => {
    load()
  }, [load])

  async function onSaveNotes(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      const r = await api.patchDevice(uuid, { notes })
      setDevice(r.item)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
    }
  }

  if (!device && !error) {
    return <div className="muted">Loading device…</div>
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1>{device?.device_name ?? device?.device_model ?? 'Device'}</h1>
          <p className="mono">{uuid}</p>
        </div>
        <div className="toolbar">
          <Link className="btn" to="/devices">
            ← Devices
          </Link>
          <button type="button" className="btn" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner error">{error}</div>}

      {device && (
        <>
          <div className="toolbar" style={{ marginBottom: '1rem' }}>
            <StatusPill status={device.status} />
            <span className="muted mono">
              last seen {formatWhen(device.last_seen)}
            </span>
          </div>

          <div className="detail-grid">
            {[
              ['Model', device.device_model],
              ['iOS', device.ios_version],
              ['Chipset', device.chipset],
              ['IP', device.ip_address],
              ['Network', device.network_type],
              ['Battery', device.battery_level != null ? `${device.battery_level}%` : null],
              ['Screen', device.screen_resolution],
              ['Defend stage', device.defend_stage],
              ['Defend chain', device.defend_chain],
              ['Runtime', device.runtime_type],
              ['Serial', device.serial_number],
              ['Locale', device.locale],
              ['Timezone', device.timezone],
              ['Memory', formatBytes(device.total_memory)],
              ['Disk', formatBytes(device.total_disk)],
              ['Created', formatWhen(device.created_at)],
            ].map(([k, v]) => (
              <div className="detail-item" key={String(k)}>
                <div className="k">{k}</div>
                <div className="v">{v ?? '—'}</div>
              </div>
            ))}
          </div>

          <form className="form-panel" onSubmit={onSaveNotes} style={{ marginTop: '1.25rem' }}>
            <div className="field">
              <label htmlFor="notes">Operator notes</label>
              <textarea
                id="notes"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
            <div>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? 'Saving…' : 'Save notes'}
              </button>
            </div>
          </form>
        </>
      )}
    </div>
  )
}
