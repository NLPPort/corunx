-- Lab-safe stand-ins for tasks / exfil / device_logs.
-- Internal research jobs, owned-test artifacts, operator/honeypot events only.

CREATE TABLE IF NOT EXISTS lab_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_uuid TEXT,
  job_type TEXT NOT NULL,
  payload TEXT,
  status TEXT DEFAULT 'pending',
  result TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  started_at TEXT,
  completed_at TEXT,
  priority INTEGER DEFAULT 0,
  retry_count INTEGER DEFAULT 0,
  timeout_seconds INTEGER DEFAULT 300,
  job_metadata TEXT,
  parent_job_id INTEGER,
  FOREIGN KEY (device_uuid) REFERENCES lab_devices (device_uuid),
  FOREIGN KEY (parent_job_id) REFERENCES lab_jobs (id)
);

CREATE INDEX IF NOT EXISTS ix_lab_jobs_device_uuid ON lab_jobs (device_uuid);
CREATE INDEX IF NOT EXISTS ix_lab_jobs_status ON lab_jobs (status);
CREATE INDEX IF NOT EXISTS ix_lab_jobs_job_type ON lab_jobs (job_type);

CREATE TABLE IF NOT EXISTS lab_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_uuid TEXT,
  category TEXT NOT NULL,
  path TEXT,
  description TEXT,
  file_size INTEGER,
  storage_path TEXT,
  content_preview TEXT,
  mime_type TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  artifact_metadata TEXT,
  job_id INTEGER,
  FOREIGN KEY (device_uuid) REFERENCES lab_devices (device_uuid),
  FOREIGN KEY (job_id) REFERENCES lab_jobs (id)
);

CREATE INDEX IF NOT EXISTS ix_lab_artifacts_device_uuid ON lab_artifacts (device_uuid);
CREATE INDEX IF NOT EXISTS ix_lab_artifacts_category ON lab_artifacts (category);
CREATE INDEX IF NOT EXISTS ix_lab_artifacts_job_id ON lab_artifacts (job_id);

CREATE TABLE IF NOT EXISTS lab_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_uuid TEXT,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  elapsed_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  event_metadata TEXT,
  log_level TEXT DEFAULT 'INFO',
  FOREIGN KEY (device_uuid) REFERENCES lab_devices (device_uuid)
);

CREATE INDEX IF NOT EXISTS ix_lab_events_device_uuid ON lab_events (device_uuid);
CREATE INDEX IF NOT EXISTS ix_lab_events_event_type ON lab_events (event_type);
CREATE INDEX IF NOT EXISTS ix_lab_events_created_at ON lab_events (created_at);
