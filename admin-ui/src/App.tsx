import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { RequireAuth } from './auth/RequireAuth'
import { Layout } from './components/Layout'
import { Artifacts } from './pages/Artifacts'
import { Dashboard } from './pages/Dashboard'
import { DeviceDetail } from './pages/DeviceDetail'
import { Devices } from './pages/Devices'
import { Events } from './pages/Events'
import { Jobs } from './pages/Jobs'
import { Login } from './pages/Login'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter basename="/console">
        <Routes>
          <Route path="login" element={<Login />} />
          <Route element={<RequireAuth />}>
            <Route element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="devices" element={<Devices />} />
              <Route path="devices/:uuid" element={<DeviceDetail />} />
              <Route path="jobs" element={<Jobs />} />
              <Route path="artifacts" element={<Artifacts />} />
              <Route path="events" element={<Events />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
