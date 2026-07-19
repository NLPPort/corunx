import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Artifacts } from './pages/Artifacts'
import { Dashboard } from './pages/Dashboard'
import { DeviceDetail } from './pages/DeviceDetail'
import { Devices } from './pages/Devices'
import { Events } from './pages/Events'
import { Jobs } from './pages/Jobs'

export default function App() {
  return (
    <BrowserRouter basename="/console">
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="devices" element={<Devices />} />
          <Route path="devices/:uuid" element={<DeviceDetail />} />
          <Route path="jobs" element={<Jobs />} />
          <Route path="artifacts" element={<Artifacts />} />
          <Route path="events" element={<Events />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
