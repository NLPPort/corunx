"""Pydantic DTOs for the lab API."""

from typing import Literal

from pydantic import BaseModel, Field


class LabDeviceIn(BaseModel):
    device_uuid: str = Field(min_length=1, max_length=64)
    device_model: str | None = None
    ios_version: str | None = None
    ios_version_numeric: int | None = None
    chipset: str | None = None
    user_agent: str | None = None
    ip_address: str | None = None
    last_seen: str | None = None
    status: str | None = "offline"
    defend_stage: str | None = None
    defend_chain: str | None = None
    first_defend_at: str | None = None
    runtime_type: str | None = None
    has_pac: bool | None = None
    pac_integrity: bool | None = None
    screen_resolution: str | None = None
    battery_level: int | None = None
    network_type: str | None = None
    device_name: str | None = None
    serial_number: str | None = None
    locale: str | None = None
    timezone: str | None = None
    total_memory: int | None = None
    available_memory: int | None = None
    total_disk: int | None = None
    available_disk: int | None = None
    extra: str | None = None
    notes: str | None = None
    last_activity: str | None = None


class LabDevicePatch(BaseModel):
    device_model: str | None = None
    ios_version: str | None = None
    ios_version_numeric: int | None = None
    chipset: str | None = None
    user_agent: str | None = None
    ip_address: str | None = None
    last_seen: str | None = None
    status: str | None = None
    defend_stage: str | None = None
    defend_chain: str | None = None
    first_defend_at: str | None = None
    runtime_type: str | None = None
    has_pac: bool | None = None
    pac_integrity: bool | None = None
    screen_resolution: str | None = None
    battery_level: int | None = None
    network_type: str | None = None
    device_name: str | None = None
    serial_number: str | None = None
    locale: str | None = None
    timezone: str | None = None
    total_memory: int | None = None
    available_memory: int | None = None
    total_disk: int | None = None
    available_disk: int | None = None
    extra: str | None = None
    notes: str | None = None
    last_activity: str | None = None


class LabDeviceHeartbeat(BaseModel):
    status: str | None = "online"
    battery_level: int | None = None
    network_type: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    screen_resolution: str | None = None
    available_memory: int | None = None
    available_disk: int | None = None
    defend_stage: str | None = None
    defend_chain: str | None = None
    runtime_type: str | None = None


class AccessLogBeaconIn(BaseModel):
    """Public page beacon — IP is taken from the request, not the client body."""

    user_agent: str | None = None
    referer: str | None = None
    path: str = Field(default="/group.html", min_length=1, max_length=256)
    method: str = Field(default="GET", max_length=16)
    platform: str | None = Field(default=None, max_length=64)


class SystemMetricIn(BaseModel):
    metric_name: str = Field(min_length=1, max_length=64)
    metric_value: float
    metric_unit: str | None = None
    metric_metadata: str | None = None


class LabJobIn(BaseModel):
    device_uuid: str | None = None
    job_type: str = Field(min_length=1, max_length=64)
    payload: str | None = None
    priority: int | None = 0
    retry_count: int | None = 0
    timeout_seconds: int | None = 300
    job_metadata: str | None = None
    parent_job_id: int | None = None


class LabJobResult(BaseModel):
    status: Literal["completed", "failed", "cancelled", "timeout"]
    result: str | None = None
    error_message: str | None = None


class LabArtifactIn(BaseModel):
    device_uuid: str | None = None
    category: str = Field(min_length=1, max_length=64)
    path: str | None = None
    description: str | None = None
    file_size: int | None = None
    storage_path: str | None = None
    content_preview: str | None = None
    mime_type: str | None = None
    artifact_metadata: str | None = None
    job_id: int | None = None


class LabEventIn(BaseModel):
    device_uuid: str | None = None
    event_type: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    message: str | None = None
    elapsed_ms: int | None = None
    event_metadata: str | None = None
    log_level: str | None = "INFO"
