"""Access logs, system metrics, table listing."""

from fastapi import APIRouter, Request

from lab.db import clamp_limit, db, rows
from lab.schemas import AccessLogIn, SystemMetricIn

router = APIRouter(prefix="/lab", tags=["lab-misc"])


@router.get("/tables")
async def list_tables(req: Request):
    result = await db(req).prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%' "
        "ORDER BY name"
    ).all()
    return {"tables": [r["name"] for r in rows(result)]}


@router.get("/access-logs")
async def list_access_logs(req: Request, limit: int = 50):
    limit = clamp_limit(limit)
    result = await db(req).prepare(
        "SELECT id, ip, user_agent, referer, path, method, created_at "
        "FROM access_logs ORDER BY id DESC LIMIT ?"
    ).bind(limit).all()
    return {"items": rows(result)}


@router.post("/access-logs")
async def create_access_log(body: AccessLogIn, req: Request):
    await db(req).prepare(
        "INSERT INTO access_logs (ip, user_agent, referer, path, method) "
        "VALUES (?, ?, ?, ?, ?)"
    ).bind(body.ip, body.user_agent, body.referer, body.path, body.method.upper()).run()
    return {"ok": True}


@router.get("/metrics")
async def list_metrics(req: Request, name: str | None = None, limit: int = 50):
    limit = clamp_limit(limit)
    if name:
        result = await db(req).prepare(
            "SELECT id, metric_name, metric_value, metric_unit, timestamp, metric_metadata "
            "FROM system_metrics WHERE metric_name = ? ORDER BY id DESC LIMIT ?"
        ).bind(name, limit).all()
    else:
        result = await db(req).prepare(
            "SELECT id, metric_name, metric_value, metric_unit, timestamp, metric_metadata "
            "FROM system_metrics ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": rows(result)}


@router.post("/metrics")
async def create_metric(body: SystemMetricIn, req: Request):
    await db(req).prepare(
        "INSERT INTO system_metrics (metric_name, metric_value, metric_unit, metric_metadata) "
        "VALUES (?, ?, ?, ?)"
    ).bind(body.metric_name, body.metric_value, body.metric_unit, body.metric_metadata).run()
    return {"ok": True}
