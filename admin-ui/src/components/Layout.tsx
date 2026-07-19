import { NavLink, Outlet } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api } from '../api/client'
import { useAuth } from '../auth/AuthContext'

const links = [
  { to: '/', label: 'Overview', end: true },
  { to: '/devices', label: 'Devices' },
  { to: '/jobs', label: 'Jobs' },
  { to: '/artifacts', label: 'Artifacts' },
  { to: '/events', label: 'Events' },
]

export function Layout() {
  const { username, logout } = useAuth()
  const [health, setHealth] = useState<string>('…')

  useEffect(() => {
    let alive = true
    api
      .health()
      .then((h) => {
        if (alive) setHealth(h.status === 'healthy' ? 'api ok' : h.status)
      })
      .catch(() => {
        if (alive) setHealth('api down')
      })
    return () => {
      alive = false
    }
  }, [])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            normal<span>cf</span>
          </div>
          <div className="brand-sub">defensive research lab</div>
        </div>
        <nav className="nav">
          {links.map((l) => (
            <NavLink key={l.to} to={l.to} end={l.end}>
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div>
            {username ?? 'admin'} · {health}
          </div>
          <button type="button" className="btn logout-btn" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
