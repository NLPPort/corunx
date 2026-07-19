-- Defensive research lab schema only (owned test devices + honeypot logs + metrics).
-- No tasking / exfil / credential / SMS / contact collection tables.
-- Apply 0002_lab_gap.sql after this for full lab inventory columns.

CREATE TABLE IF NOT EXISTS lab_devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_uuid TEXT NOT NULL UNIQUE,
  device_model TEXT,
  ios_version TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS ix_lab_devices_device_uuid ON lab_devices (device_uuid);

CREATE TABLE IF NOT EXISTS access_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  user_agent TEXT,
  path TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS ix_access_logs_created_at ON access_logs (created_at);
CREATE INDEX IF NOT EXISTS ix_access_logs_ip ON access_logs (ip);

CREATE TABLE IF NOT EXISTS system_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  metric_unit TEXT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS ix_system_metrics_name ON system_metrics (metric_name);
CREATE INDEX IF NOT EXISTS ix_system_metrics_timestamp ON system_metrics (timestamp);
