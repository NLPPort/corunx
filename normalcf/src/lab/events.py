"""Operator / honeypot event timeline."""

from fastapi import APIRouter, Depends, Request

from lab.auth import require_admin
from lab.columns import LAB_EVENT_COLUMNS
from lab.db import clamp_limit, db, rows
from lab.schemas import LabEventIn

router = APIRouter(
    prefix="/lab/events",
    tags=["events"],
    dependencies=[Depends(require_admin)],
)


@router.get("")
async def list_events(
    req: Request,
    device_uuid: str | None = None,
    event_type: str | None = None,
    limit: int = 50,
):
    limit = clamp_limit(limit)
    if device_uuid and event_type:
        result = await db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events "
            "WHERE device_uuid = ? AND event_type = ? ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, event_type, limit).all()
    elif device_uuid:
        result = await db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    elif event_type:
        result = await db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events WHERE event_type = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(event_type, limit).all()
    else:
        result = await db(req).prepare(
            f"SELECT {LAB_EVENT_COLUMNS} FROM lab_events ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": rows(result)}


@router.post("")
async def create_event(body: LabEventIn, req: Request):
    await db(req).prepare(
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
