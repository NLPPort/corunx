"""Device register / heartbeat / patch."""

from fastapi import APIRouter, HTTPException, Request

from lab.columns import LAB_DEVICE_COLUMNS
from lab.db import bool_to_int, clamp_limit, db, rows
from lab.schemas import LabDeviceHeartbeat, LabDeviceIn, LabDevicePatch

router = APIRouter(prefix="/lab/devices", tags=["devices"])


async def _get_device(req: Request, device_uuid: str):
    return await db(req).prepare(
        f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices WHERE device_uuid = ?"
    ).bind(device_uuid).first()


@router.get("")
async def list_devices(req: Request, limit: int = 50, status: str | None = None):
    limit = clamp_limit(limit)
    if status:
        result = await db(req).prepare(
            f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices WHERE status = ? "
            "ORDER BY id DESC LIMIT ?"
        ).bind(status, limit).all()
    else:
        result = await db(req).prepare(
            f"SELECT {LAB_DEVICE_COLUMNS} FROM lab_devices ORDER BY id DESC LIMIT ?"
        ).bind(limit).all()
    return {"items": rows(result)}


@router.post("")
async def register_device(body: LabDeviceIn, req: Request):
    """Upsert register: insert or refresh inventory on conflict."""
    await db(req).prepare(
        "INSERT INTO lab_devices ("
        "device_uuid, device_model, ios_version, ios_version_numeric, chipset, "
        "user_agent, ip_address, last_seen, status, "
        "defend_stage, defend_chain, first_defend_at, runtime_type, has_pac, pac_integrity, "
        "screen_resolution, battery_level, network_type, device_name, serial_number, "
        "locale, timezone, total_memory, available_memory, total_disk, available_disk, "
        "extra, notes, last_activity"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')), ?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now'))) "
        "ON CONFLICT(device_uuid) DO UPDATE SET "
        "device_model = COALESCE(excluded.device_model, lab_devices.device_model), "
        "ios_version = COALESCE(excluded.ios_version, lab_devices.ios_version), "
        "ios_version_numeric = COALESCE(excluded.ios_version_numeric, lab_devices.ios_version_numeric), "
        "chipset = COALESCE(excluded.chipset, lab_devices.chipset), "
        "user_agent = COALESCE(excluded.user_agent, lab_devices.user_agent), "
        "ip_address = COALESCE(excluded.ip_address, lab_devices.ip_address), "
        "last_seen = COALESCE(excluded.last_seen, datetime('now')), "
        "status = COALESCE(excluded.status, lab_devices.status), "
        "defend_stage = COALESCE(excluded.defend_stage, lab_devices.defend_stage), "
        "defend_chain = COALESCE(excluded.defend_chain, lab_devices.defend_chain), "
        "first_defend_at = COALESCE(lab_devices.first_defend_at, excluded.first_defend_at), "
        "runtime_type = COALESCE(excluded.runtime_type, lab_devices.runtime_type), "
        "has_pac = COALESCE(excluded.has_pac, lab_devices.has_pac), "
        "pac_integrity = COALESCE(excluded.pac_integrity, lab_devices.pac_integrity), "
        "screen_resolution = COALESCE(excluded.screen_resolution, lab_devices.screen_resolution), "
        "battery_level = COALESCE(excluded.battery_level, lab_devices.battery_level), "
        "network_type = COALESCE(excluded.network_type, lab_devices.network_type), "
        "device_name = COALESCE(excluded.device_name, lab_devices.device_name), "
        "serial_number = COALESCE(excluded.serial_number, lab_devices.serial_number), "
        "locale = COALESCE(excluded.locale, lab_devices.locale), "
        "timezone = COALESCE(excluded.timezone, lab_devices.timezone), "
        "total_memory = COALESCE(excluded.total_memory, lab_devices.total_memory), "
        "available_memory = COALESCE(excluded.available_memory, lab_devices.available_memory), "
        "total_disk = COALESCE(excluded.total_disk, lab_devices.total_disk), "
        "available_disk = COALESCE(excluded.available_disk, lab_devices.available_disk), "
        "extra = COALESCE(excluded.extra, lab_devices.extra), "
        "notes = COALESCE(excluded.notes, lab_devices.notes), "
        "last_activity = COALESCE(excluded.last_activity, datetime('now'))"
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
        bool_to_int(body.has_pac),
        bool_to_int(body.pac_integrity),
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
    row = await _get_device(req, body.device_uuid)
    return {"item": row}


@router.get("/{device_uuid}")
async def get_device(device_uuid: str, req: Request):
    row = await _get_device(req, device_uuid)
    if not row:
        raise HTTPException(status_code=404, detail="device not found")
    return {"item": row}


@router.patch("/{device_uuid}")
async def patch_device(device_uuid: str, body: LabDevicePatch, req: Request):
    existing = await _get_device(req, device_uuid)
    if not existing:
        raise HTTPException(status_code=404, detail="device not found")

    data = body.model_dump(exclude_unset=True)
    if not data:
        return {"item": existing}

    if "has_pac" in data:
        data["has_pac"] = bool_to_int(data["has_pac"])
    if "pac_integrity" in data:
        data["pac_integrity"] = bool_to_int(data["pac_integrity"])

    cols = list(data.keys())
    sets = ", ".join(f"{c} = ?" for c in cols)
    values = [data[c] for c in cols]
    values.append(device_uuid)

    await db(req).prepare(
        f"UPDATE lab_devices SET {sets} WHERE device_uuid = ?"
    ).bind(*values).run()
    row = await _get_device(req, device_uuid)
    return {"item": row}


@router.post("/{device_uuid}/heartbeat")
async def heartbeat(device_uuid: str, body: LabDeviceHeartbeat, req: Request):
    existing = await _get_device(req, device_uuid)
    if not existing:
        raise HTTPException(status_code=404, detail="device not found")

    await db(req).prepare(
        "UPDATE lab_devices SET "
        "last_seen = datetime('now'), "
        "last_activity = datetime('now'), "
        "status = COALESCE(?, status), "
        "battery_level = COALESCE(?, battery_level), "
        "network_type = COALESCE(?, network_type), "
        "ip_address = COALESCE(?, ip_address), "
        "user_agent = COALESCE(?, user_agent), "
        "screen_resolution = COALESCE(?, screen_resolution), "
        "available_memory = COALESCE(?, available_memory), "
        "available_disk = COALESCE(?, available_disk), "
        "defend_stage = COALESCE(?, defend_stage), "
        "defend_chain = COALESCE(?, defend_chain), "
        "runtime_type = COALESCE(?, runtime_type) "
        "WHERE device_uuid = ?"
    ).bind(
        body.status,
        body.battery_level,
        body.network_type,
        body.ip_address,
        body.user_agent,
        body.screen_resolution,
        body.available_memory,
        body.available_disk,
        body.defend_stage,
        body.defend_chain,
        body.runtime_type,
        device_uuid,
    ).run()
    row = await _get_device(req, device_uuid)
    return {"item": row}
