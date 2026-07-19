"""Admin read model: aggregate lab stats."""

from fastapi import APIRouter, Depends, Request

from lab.auth import require_admin
from lab.columns import LAB_ARTIFACT_COLUMNS, LAB_DEVICE_COLUMNS, LAB_JOB_COLUMNS
from lab.db import clamp_limit, db, rows

router = APIRouter(
    prefix="/lab/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


async def _count(req: Request, sql: str, *binds) -> int:
    stmt = db(req).prepare(sql)
    row = await (stmt.bind(*binds).first() if binds else stmt.first())
    if not row:
        return 0
    val = row["n"] if isinstance(row, dict) else row.n
    return int(val or 0)


@router.get("/stats")
async def admin_stats(req: Request, recent: int = 10):
    recent = clamp_limit(recent, default=10, max_limit=50)

    total_devices = await _count(req, "SELECT COUNT(*) AS n FROM lab_devices")
    online_devices = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_devices WHERE status = 'online'"
    )
    offline_devices = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_devices WHERE status = 'offline'"
    )
    busy_devices = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_devices WHERE status = 'busy'"
    )

    total_jobs = await _count(req, "SELECT COUNT(*) AS n FROM lab_jobs")
    pending_jobs = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_jobs WHERE status = 'pending'"
    )
    running_jobs = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_jobs WHERE status = 'running'"
    )
    completed_jobs = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_jobs WHERE status = 'completed'"
    )
    failed_jobs = await _count(
        req, "SELECT COUNT(*) AS n FROM lab_jobs WHERE status = 'failed'"
    )

    total_artifacts = await _count(req, "SELECT COUNT(*) AS n FROM lab_artifacts")
    size_row = await db(req).prepare(
        "SELECT COALESCE(SUM(file_size), 0) AS n FROM lab_artifacts"
    ).first()
    total_artifact_bytes = int(
        (size_row["n"] if isinstance(size_row, dict) else size_row.n) if size_row else 0
    )

    total_events = await _count(req, "SELECT COUNT(*) AS n FROM lab_events")

    recent_devices = rows(
        await db(req).prepare(
            f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices ORDER BY id DESC LIMIT ?"
        ).bind(recent).all()
    )
    recent_jobs = rows(
        await db(req).prepare(
            f"SELECT {LAB_JOB_COLUMNS} FROM lab_jobs ORDER BY id DESC LIMIT ?"
        ).bind(recent).all()
    )
    recent_artifacts = rows(
        await db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts ORDER BY id DESC LIMIT ?"
        ).bind(recent).all()
    )

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": offline_devices,
        "busy_devices": busy_devices,
        "total_jobs": total_jobs,
        "pending_jobs": pending_jobs,
        "running_jobs": running_jobs,
        "completed_jobs": completed_jobs,
        "failed_jobs": failed_jobs,
        "total_artifacts": total_artifacts,
        "total_artifact_bytes": total_artifact_bytes,
        "total_events": total_events,
        "recent_devices": recent_devices,
        "recent_jobs": recent_jobs,
        "recent_artifacts": recent_artifacts,
    }
