"""Access logs, system metrics, table listing."""

from fastapi import APIRouter, Depends, Request

from lab.auth import require_admin
from lab.db import clamp_limit, db, rows
from lab.schemas import AccessLogBeaconIn, SystemMetricIn

router = APIRouter(
    prefix="/lab",
    tags=["lab-misc"],
    dependencies=[Depends(require_admin)],
)

# Public visitor beacons (e.g. group.html) — no admin token required.
public_router = APIRouter(prefix="/lab", tags=["lab-misc-public"])


def _client_ip(req: Request) -> str:
    h = req.headers
    ip = h.get("cf-connecting-ip") or h.get("x-real-ip")
    if not ip:
        xff = h.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
    if not ip:
        client = req.client
        ip = client.host if client else "0.0.0.0"
    return (ip or "0.0.0.0")[:64]


def _ua_with_platform(user_agent: str | None, platform: str | None) -> str | None:
    if not platform:
        return user_agent
    tag = f"[platform={platform}]"
    if not user_agent:
        return tag
    return f"{user_agent} {tag}"[:2048]


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


@public_router.post("/access-logs")
async def create_access_log(body: AccessLogBeaconIn, req: Request):
    ua = _ua_with_platform(body.user_agent, body.platform)
    referer = body.referer or req.headers.get("referer")
    await db(req).prepare(
        "INSERT INTO access_logs (ip, user_agent, referer, path, method) "
        "VALUES (?, ?, ?, ?, ?)"
    ).bind(
        _client_ip(req),
        ua,
        referer,
        body.path,
        body.method.upper(),
    ).run()
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
