"""D1 helpers for the lab API."""

from fastapi import Request


def db(req: Request):
    return req.scope["env"].DB


def rows(result):
    """Normalize D1 result rows to plain Python lists/dicts."""
    results = getattr(result, "results", None)
    if results is None:
        return []
    to_py = getattr(results, "to_py", None)
    if callable(to_py):
        return to_py()
    return list(results)


def last_row_id(result) -> int | None:
    meta = getattr(result, "meta", None)
    if meta is None:
        return None
    rid = getattr(meta, "last_row_id", None)
    if rid is not None:
        return int(rid)
    if isinstance(meta, dict) and meta.get("last_row_id") is not None:
        return int(meta["last_row_id"])
    return None


def changes(result) -> int:
    meta = getattr(result, "meta", None)
    if meta is None:
        return 0
    n = getattr(meta, "changes", None)
    if n is not None:
        return int(n)
    if isinstance(meta, dict):
        return int(meta.get("changes") or 0)
    return 0


def clamp_limit(limit: int, default: int = 50, max_limit: int = 200) -> int:
    if limit is None:
        return default
    return max(1, min(int(limit), max_limit))


def bool_to_int(value: bool | None) -> int | None:
    if value is None:
        return None
    return int(value)
