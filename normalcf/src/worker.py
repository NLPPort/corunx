"""FastAPI + D1 lab DB (defensive research: devices, access logs, metrics)."""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from workers import WorkerEntrypoint

app = FastAPI(title="normalcf", docs_url="/docs", redoc_url=None)

LAB_DEVICE_COLUMNS = (
    "id, device_uuid, device_model, ios_version, ios_version_numeric, chipset, "
    "user_agent, ip_address, last_seen, created_at, status, "
    "defend_stage, defend_chain, first_defend_at, runtime_type, has_pac, pac_integrity, "
    "screen_resolution, battery_level, network_type, device_name, serial_number, "
    "locale, timezone, total_memory, available_memory, total_disk, available_disk, "
    "extra, notes, last_activity"
)


def _db(req: Request):
    return req.scope["env"].DB


def _rows(result):
    """Normalize D1 result rows to plain Python lists/dicts."""
    results = getattr(result, "results", None)
    if results is None:
        return []
    to_py = getattr(results, "to_py", None)
    if callable(to_py):
        return to_py()
    return list(results)


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


class AccessLogIn(BaseModel):
    ip: str = Field(min_length=1, max_length=64)
    user_agent: str | None = None
    referer: str | None = None
    path: str = Field(min_length=1, max_length=256)
    method: str = Field(default="GET", max_length=16)


class SystemMetricIn(BaseModel):
    metric_name: str = Field(min_length=1, max_length=64)
    metric_value: float
    metric_unit: str | None = None
    metric_metadata: str | None = None


class LabJobIn(BaseModel):
    device_uuid: str | None = None
    job_type: str = Field(min_length=1, max_length=64)
    payload: str | None = None
    status: str | None = "pending"
    result: str | None = None
    error_message: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    priority: int | None = 0
    retry_count: int | None = 0
    timeout_seconds: int | None = 300
    job_metadata: str | None = None
    parent_job_id: int | None = None


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


@app.get("/")
async def root():
    return {"ok": True, "service": "normalcf", "runtime": "fastapi", "db": "d1-lab"}


@app.get("/health")
async def health(req: Request):
    try:
        await _db(req).prepare("SELECT 1 AS ok").first()
        return {"status": "healthy", "db": "ok"}
    except Exception as e:
        return {"status": "degraded", "db": str(e)}


@app.get("/hello/{name}")
async def hello(name: str):
    return {"message": f"hello, {name}"}


@app.get("/lab/tables")
async def list_tables(req: Request):
    result = await _db(req).prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%' ORDER BY name"
    ).all()
    return {"tables": [r["name"] for r in _rows(result)]}


# --- lab_devices ---

@app.get("/lab/devices")
async def list_devices(req: Request, limit: int = 50):
    limit = max(1, min(limit, 200))
    result = await _db(req).prepare(
        f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices ORDER BY id DESC LIMIT ?"
    ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/devices")
async def create_device(body: LabDeviceIn, req: Request):
    try:
        await _db(req).prepare(
            "INSERT INTO lab_devices ("
            "device_uuid, device_model, ios_version, ios_version_numeric, chipset, "
            "user_agent, ip_address, last_seen, status, "
            "defend_stage, defend_chain, first_defend_at, runtime_type, has_pac, pac_integrity, "
            "screen_resolution, battery_level, network_type, device_name, serial_number, "
            "locale, timezone, total_memory, available_memory, total_disk, available_disk, "
            "extra, notes, last_activity"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(
            body.device_uuid,
            body.device_model,
            body.ios_version,
            body.ios_version_numeric,
            body.chipset,
            body.user_agent,
            body.ip_address,
            body.last_seen,
            body.status,
            body.defend_stage,
            body.defend_chain,
            body.first_defend_at,
            body.runtime_type,
            None if body.has_pac is None else int(body.has_pac),
            None if body.pac_integrity is None else int(body.pac_integrity),
            body.screen_resolution,
            body.battery_level,
            body.network_type,
            body.device_name,
            body.serial_number,
            body.locale,
            body.timezone,
            body.total_memory,
            body.available_memory,
            body.total_disk,
            body.available_disk,
            body.extra,
            body.notes,
            body.last_activity,
        ).run()
    except Exception as e:
        raise HTTPException(status_code=409, detail=f"insert failed: {e}") from e
    row = await _db(req).prepare(
        f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices WHERE device_uuid = ?"
    ).bind(body.device_uuid).first()
    return {"item": row}


@app.get("/lab/devices/{device_uuid}")
async def get_device(device_uuid: str, req: Request):
    row = await _db(req).prepare(
        f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices WHERE device_uuid = ?"
    ).bind(device_uuid).first()
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    return {"item": row}


# --- access_logs ---

@app.get("/lab/access-logs")
async def list_access_logs(req: Request, limit: int = 50):
    limit = max(1, min(limit, 200))
    result = await _db(req).prepare(
        "SELECT id, ip, user_agent, referer, path, method, created_at "
        "FROM access_logs ORDER BY id DESC LIMIT ?"
    ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/access-logs")
async def create_access_log(body: AccessLogIn, req: Request):
    await _db(req).prepare(
        "INSERT INTO access_logs (ip, user_agent, referer, path, method) VALUES (?, ?, ?, ?, ?)"
    ).bind(body.ip, body.user_agent, body.referer, body.path, body.method.upper()).run()
    return {"ok": True}


# --- system_metrics ---

@app.get("/lab/metrics")
async def list_metrics(req: Request, name: str | None = None, limit: int = 50):
    limit = max(1, min(limit, 200))
    if name:
        result = await _db(req).prepare(
            "SELECT id, metric_name, metric_value, metric_unit, timestamp, metric_metadata "
            "FROM system_metrics WHERE metric_name = ? ORDER BY id DESC LIMIT ?"
        ).bind(name, limit).all()
    else:
        result = await _db(req).prepare(
            "SELECT id, metric_name, metric_value, metric_unit, timestamp, metric_metadata "
            "FROM system_metrics ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/metrics")
async def create_metric(body: SystemMetricIn, req: Request):
    await _db(req).prepare(
        "INSERT INTO system_metrics (metric_name, metric_value, metric_unit, metric_metadata) "
        "VALUES (?, ?, ?, ?)"
    ).bind(body.metric_name, body.metric_value, body.metric_unit, body.metric_metadata).run()
    return {"ok": True}


# --- lab_jobs (research jobs; not remote device tasking) ---

LAB_JOB_COLUMNS = (
    "id, device_uuid, job_type, payload, status, result, error_message, "
    "created_at, started_at, completed_at, priority, retry_count, timeout_seconds, "
    "job_metadata, parent_job_id"
)


@app.get("/lab/jobs")
async def list_jobs(req: Request, device_uuid: str | None = None, limit: int = 50):
    limit = max(1, min(limit, 200))
    if device_uuid:
        result = await _db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    else:
        result = await _db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/jobs")
async def create_job(body: LabJobIn, req: Request):
    await _db(req).prepare(
        "INSERT INTO lab_jobs ("
        "device_uuid, job_type, payload, status, result, error_message, "
        "started_at, completed_at, priority, retry_count, timeout_seconds, "
        "job_metadata, parent_job_id"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
        body.device_uuid,
        body.job_type,
        body.payload,
        body.status,
        body.result,
        body.error_message,
        body.started_at,
        body.completed_at,
        body.priority,
        body.retry_count,
        body.timeout_seconds,
        body.job_metadata,
        body.parent_job_id,
    ).run()
    row = await _db(req).prepare(
        f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs ORDER BY id DESC LIMIT 1"
    ).first()
    return {"item": row}


@app.get("/lab/jobs/{job_id}")
async def get_job(job_id: int, req: Request):
    row = await _db(req).prepare(
        f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs WHERE id = ?"
    ).bind(job_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="job not found")
    return {"item": row}


# --- lab_artifacts (owned test captures; not exfil) ---

LAB_ARTIFACT_COLUMNS = (
    "id, device_uuid, category, path, description, file_size, storage_path, "
    "content_preview, mime_type, created_at, artifact_metadata, job_id"
)


@app.get("/lab/artifacts")
async def list_artifacts(req: Request, device_uuid: str | None = None, limit: int = 50):
    limit = max(1, min(limit, 200))
    if device_uuid:
        result = await _db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    else:
        result = await _db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/artifacts")
async def create_artifact(body: LabArtifactIn, req: Request):
    await _db(req).prepare(
        "INSERT INTO lab_artifacts ("
        "device_uuid, category, path, description, file_size, storage_path, "
        "content_preview, mime_type, artifact_metadata, job_id"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
        body.device_uuid,
        body.category,
        body.path,
        body.description,
        body.file_size,
        body.storage_path,
        body.content_preview,
        body.mime_type,
        body.artifact_metadata,
        body.job_id,
    ).run()
    row = await _db(req).prepare(
        f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts ORDER BY id DESC LIMIT 1"
    ).first()
    return {"item": row}


# --- lab_events (operator/honeypot events; not exploit stage logs) ---

LAB_EVENT_COLUMNS = (
    "id, device_uuid, event_type, status, message, elapsed_ms, created_at, "
    "event_metadata, log_level"
)


@app.get("/lab/events")
async def list_events(req: Request, device_uuid: str | None = None, limit: int = 50):
    limit = max(1, min(limit, 200))
    if device_uuid:
        result = await _db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    else:
        result = await _db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": _rows(result)}


@app.post("/lab/events")
async def create_event(body: LabEventIn, req: Request):
    await _db(req).prepare(
        "INSERT INTO lab_events ("
        "device_uuid, event_type, status, message, elapsed_ms, event_metadata, log_level"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(
        body.device_uuid,
        body.event_type,
        body.status,
        body.message,
        body.elapsed_ms,
        body.event_metadata,
        body.log_level,
    ).run()
    return {"ok": True}


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)
