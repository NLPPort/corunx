-- Rename coruna exploit_* device fields to defend_* for lab tracking.

ALTER TABLE lab_devices ADD COLUMN defend_stage TEXT;
ALTER TABLE lab_devices ADD COLUMN defend_chain TEXT;
ALTER TABLE lab_devices ADD COLUMN first_defend_at TEXT;
ALTER TABLE lab_devices ADD COLUMN runtime_type TEXT;
ALTER TABLE lab_devices ADD COLUMN has_pac INTEGER;
ALTER TABLE lab_devices ADD COLUMN pac_integrity INTEGER;

CREATE INDEX IF NOT EXISTS ix_lab_devices_defend_stage ON lab_devices (defend_stage);
