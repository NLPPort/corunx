"""Owned-test artifact metadata (not exfil)."""

from fastapi import APIRouter, Depends, HTTPException, Request

from lab.auth import require_admin
from lab.columns import LAB_ARTIFACT_COLUMNS
from lab.db import clamp_limit, db, last_row_id, rows
from lab.schemas import LabArtifactIn

router = APIRouter(
    prefix="/lab/artifacts",
    tags=["artifacts"],
    dependencies=[Depends(require_admin)],
)


async def _get_artifact(req: Request, artifact_id: int):
    return await db(req).prepare(
        f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts WHERE id = ?"
    ).bind(artifact_id).first()


@router.get("")
async def list_artifacts(
    req: Request,
    device_uuid: str | None = None,
    category: str | None = None,
    limit: int = 50,
):
    limit = clamp_limit(limit)
    if device_uuid and category:
        result = await db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts "
            "WHERE device_uuid = ? AND category = ? ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, category, limit).all()
    elif device_uuid:
        result = await db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts WHERE device_uuid = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(device_uuid, limit).all()
    elif category:
        result = await db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts WHERE category = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(category, limit).all()
    else:
        result = await db(req).prepare(
            f"SELECT {LAB_ARTIFACT_COLUMNS} FROM lab_artifacts ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": rows(result)}


@router.post("")
async def create_artifact(body: LabArtifactIn, req: Request):
    result = await db(req).prepare(
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
    artifact_id = last_row_id(result)
    if artifact_id is None:
        raise HTTPException(status_code=500, detail="insert did not return row id")
    row = await _get_artifact(req, artifact_id)
    return {"item": row}


@router.get("/{artifact_id}")
async def get_artifact(artifact_id: int, req: Request):
    row = await _get_artifact(req, artifact_id)
    if not row:
        raise HTTPException(status_code=404, detail="artifact not found")
    return {"item": row}
