"""Lab jobs: create, poll/claim, result."""

from fastapi import APIRouter, HTTPException, Request

from lab.columns import LAB_JOB_COLUMNS
from lab.db import changes, clamp_limit, db, last_row_id, rows
from lab.schemas import LabJobIn, LabJobResult

router = APIRouter(prefix="/lab/jobs", tags=["jobs"])

_TERMINAL = frozenset({"completed", "failed", "cancelled", "timeout"})
_POLL_ATTEMPTS = 5


async def _get_job(req: Request, job_id: int):
    return await db(req).prepare(
        f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs WHERE id = ?"
    ).bind(job_id).first()


@router.get("")
async def list_jobs(
    req: Request,
    device_uuid: str | None = None,
    status: str | None = None,
    limit: int = 50,
):
    limit = clamp_limit(limit)
    if device_uuid and status:
        result = await db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs "
            "WHERE device_uuid = ? AND status = ? ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, status, limit).all()
    elif device_uuid:
        result = await db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    elif status:
        result = await db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs WHERE status = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(status, limit).all()
    else:
        result = await db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": rows(result)}


@router.post("")
async def create_job(body: LabJobIn, req: Request):
    """Create a pending research job (status always starts as pending)."""
    result = await db(req).prepare(
        "INSERT INTO lab_jobs ("
        "device_uuid, job_type, payload, status, "
        "priority, retry_count, timeout_seconds, job_metadata, parent_job_id"
        ") VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)"
    ).bind(
        body.device_uuid,
        body.job_type,
        body.payload,
        body.priority if body.priority is not None else 0,
        body.retry_count if body.retry_count is not None else 0,
        body.timeout_seconds if body.timeout_seconds is not None else 300,
        body.job_metadata,
        body.parent_job_id,
    ).run()
    job_id = last_row_id(result)
    if job_id is None:
        raise HTTPException(status_code=500, detail="insert did not return row id")
    row = await _get_job(req, job_id)
    return {"item": row}


@router.post("/poll")
async def poll_jobs(
    req: Request,
    device_uuid: str,
    limit: int = 1,
):
    """
    Claim next pending job(s) for a device.
    Sets status=running and started_at. Retries on claim races.
    """
    limit = clamp_limit(limit, default=1, max_limit=10)
    claimed = []

    for _ in range(limit):
        job = None
        for _attempt in range(_POLL_ATTEMPTS):
            pending = await db(req).prepare(
                "SELECT id FROM lab_jobs "
                "WHERE device_uuid = ? AND status = 'pending' "
                "ORDER BY priority DESC, id ASC LIMIT 1"
            ).bind(device_uuid).first()
            if not pending:
                break
            pending_id = pending["id"] if isinstance(pending, dict) else pending.id
            upd = await db(req).prepare(
                "UPDATE lab_jobs SET status = 'running', started_at = datetime('now') "
                "WHERE id = ? AND status = 'pending'"
            ).bind(pending_id).run()
            if changes(upd) == 1:
                job = await _get_job(req, int(pending_id))
                break
        if not job:
            break
        claimed.append(job)

    return {"items": claimed, "claimed": len(claimed)}


@router.get("/{job_id}")
async def get_job(job_id: int, req: Request):
    row = await _get_job(req, job_id)
    if not row:
        raise HTTPException(status_code=404, detail="job not found")
    return {"item": row}


@router.post("/{job_id}/result")
async def submit_result(job_id: int, body: LabJobResult, req: Request):
    row = await _get_job(req, job_id)
    if not row:
        raise HTTPException(status_code=404, detail="job not found")

    current = row["status"] if isinstance(row, dict) else row.status
    if current in _TERMINAL:
        raise HTTPException(status_code=409, detail=f"job already {current}")

    if body.status == "cancelled":
        if current not in ("pending", "running"):
            raise HTTPException(
                status_code=409, detail=f"cannot cancel job in status {current}"
            )
    elif current != "running":
        raise HTTPException(
            status_code=409,
            detail=f"result requires running job, current status is {current}",
        )

    await db(req).prepare(
        "UPDATE lab_jobs SET status = ?, result = ?, error_message = ?, "
        "completed_at = datetime('now') WHERE id = ?"
    ).bind(body.status, body.result, body.error_message, job_id).run()
    updated = await _get_job(req, job_id)
    return {"item": updated}
