"""Admin session tokens (HMAC) for protecting /lab data APIs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "123123admin"
DEFAULT_SESSION_SECRET = "normalcf-lab-dev-secret-change-me"
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _env(req: Request):
    return req.scope["env"]


def admin_user(req: Request) -> str:
    env = _env(req)
    return getattr(env, "ADMIN_USER", None) or DEFAULT_ADMIN_USER


def admin_password(req: Request) -> str:
    env = _env(req)
    return getattr(env, "ADMIN_PASSWORD", None) or DEFAULT_ADMIN_PASSWORD


def session_secret(req: Request) -> str:
    env = _env(req)
    return getattr(env, "SESSION_SECRET", None) or DEFAULT_SESSION_SECRET


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def mint_token(req: Request, username: str) -> dict[str, Any]:
    exp = int(time.time()) + TOKEN_TTL_SECONDS
    payload = {"sub": username, "exp": exp}
    body = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    sig = _b64url_encode(
        hmac.new(
            session_secret(req).encode("utf-8"),
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    return {"token": f"{body}.{sig}", "expires_at": exp, "username": username}


def verify_token(req: Request, token: str) -> dict[str, Any]:
    try:
        body, sig = token.split(".", 1)
    except ValueError as e:
        raise HTTPException(status_code=401, detail="invalid token") from e

    expected = _b64url_encode(
        hmac.new(
            session_secret(req).encode("utf-8"),
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401, detail="invalid token")

    try:
        payload = json.loads(_b64url_decode(body))
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=401, detail="invalid token") from e

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="token expired")

    return payload


async def require_admin(
    req: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=401, detail="authentication required")
    return verify_token(req, creds.credentials)
