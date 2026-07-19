"""Shared SELECT column lists."""

LAB_DEVICE_COLUMNS = (
    "id, device_uuid, device_model, ios_version, ios_version_numeric, chipset, "
    "user_agent, ip_address, last_seen, created_at, status, "
    "defend_stage, defend_chain, first_defend_at, runtime_type, has_pac, pac_integrity, "
    "screen_resolution, battery_level, network_type, device_name, serial_number, "
    "locale, timezone, total_memory, available_memory, total_disk, available_disk, "
    "extra, notes, last_activity"
)

LAB_JOB_COLUMNS = (
    "id, device_uuid, job_type, payload, status, result, error_message, "
    "created_at, started_at, completed_at, priority, retry_count, timeout_seconds, "
    "job_metadata, parent_job_id"
)

LAB_ARTIFACT_COLUMNS = (
    "id, device_uuid, category, path, description, file_size, storage_path, "
    "content_preview, mime_type, created_at, artifact_metadata, job_id"
)

LAB_EVENT_COLUMNS = (
    "id, device_uuid, event_type, status, message, elapsed_ms, created_at, "
    "event_metadata, log_level"
)
