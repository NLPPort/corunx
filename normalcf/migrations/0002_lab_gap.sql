-- Close safe gaps vs coruna inventory/logging tables.
-- Still no tasking / exfil / SMS / contacts / keychain / similar collection tables.

-- access_logs: match coruna (+ referer)
ALTER TABLE access_logs ADD COLUMN referer TEXT;

-- system_metrics: match coruna (+ metric_metadata JSON as TEXT)
ALTER TABLE system_metrics ADD COLUMN metric_metadata TEXT;

-- lab_devices: inventory fields from devices (lab asset tracking only)
ALTER TABLE lab_devices ADD COLUMN ios_version_numeric INTEGER;
ALTER TABLE lab_devices ADD COLUMN chipset TEXT;
ALTER TABLE lab_devices ADD COLUMN user_agent TEXT;
ALTER TABLE lab_devices ADD COLUMN ip_address TEXT;
ALTER TABLE lab_devices ADD COLUMN last_seen TEXT;
ALTER TABLE lab_devices ADD COLUMN status TEXT DEFAULT 'offline';
ALTER TABLE lab_devices ADD COLUMN screen_resolution TEXT;
ALTER TABLE lab_devices ADD COLUMN battery_level INTEGER;
ALTER TABLE lab_devices ADD COLUMN network_type TEXT;
ALTER TABLE lab_devices ADD COLUMN device_name TEXT;
ALTER TABLE lab_devices ADD COLUMN serial_number TEXT;
ALTER TABLE lab_devices ADD COLUMN locale TEXT;
ALTER TABLE lab_devices ADD COLUMN timezone TEXT;
ALTER TABLE lab_devices ADD COLUMN total_memory INTEGER;
ALTER TABLE lab_devices ADD COLUMN available_memory INTEGER;
ALTER TABLE lab_devices ADD COLUMN total_disk INTEGER;
ALTER TABLE lab_devices ADD COLUMN available_disk INTEGER;
ALTER TABLE lab_devices ADD COLUMN extra TEXT;
ALTER TABLE lab_devices ADD COLUMN last_activity TEXT;

CREATE INDEX IF NOT EXISTS ix_lab_devices_status ON lab_devices (status);
CREATE INDEX IF NOT EXISTS ix_lab_devices_last_seen ON lab_devices (last_seen);
