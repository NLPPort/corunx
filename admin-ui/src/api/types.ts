export type Device = {
  id: number
  device_uuid: string
  device_model: string | null
  ios_version: string | null
  ios_version_numeric: number | null
  chipset: string | null
  user_agent: string | null
  ip_address: string | null
  last_seen: string | null
  created_at: string | null
  status: string | null
  defend_stage: string | null
  defend_chain: string | null
  first_defend_at: string | null
  runtime_type: string | null
  has_pac: number | null
  pac_integrity: number | null
  screen_resolution: string | null
  battery_level: number | null
  network_type: string | null
  device_name: string | null
  serial_number: string | null
  locale: string | null
  timezone: string | null
  total_memory: number | null
  available_memory: number | null
  total_disk: number | null
  available_disk: number | null
  extra: string | null
  notes: string | null
  last_activity: string | null
}

export type Job = {
  id: number
  device_uuid: string | null
  job_type: string
  payload: string | null
  status: string | null
  result: string | null
  error_message: string | null
  created_at: string | null
  started_at: string | null
  completed_at: string | null
  priority: number | null
  retry_count: number | null
  timeout_seconds: number | null
  job_metadata: string | null
  parent_job_id: number | null
}

export type Artifact = {
  id: number
  device_uuid: string | null
  category: string
  path: string | null
  description: string | null
  file_size: number | null
  storage_path: string | null
  content_preview: string | null
  mime_type: string | null
  created_at: string | null
  artifact_metadata: string | null
  job_id: number | null
}

export type Event = {
  id: number
  device_uuid: string | null
  event_type: string
  status: string
  message: string | null
  elapsed_ms: number | null
  created_at: string | null
  event_metadata: string | null
  log_level: string | null
}

export type AdminStats = {
  total_devices: number
  online_devices: number
  offline_devices: number
  busy_devices: number
  total_jobs: number
  pending_jobs: number
  running_jobs: number
  completed_jobs: number
  failed_jobs: number
  total_artifacts: number
  total_artifact_bytes: number
  total_events: number
  recent_devices: Device[]
  recent_jobs: Job[]
  recent_artifacts: Artifact[]
}

export type Items<T> = { items: T[] }
