"""Admin login / session."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from lab.auth import (
    admin_password,
    admin_user,
    mint_token,
    require_admin,
)

router = APIRouter(prefix="/lab/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


@router.post("/login")
async def login(body: LoginIn, req: Request):
    user = admin_user(req)
    password = admin_password(req)
    if body.username != user or body.password != password:
        raise HTTPException(status_code=401, detail="invalid username or password")
    return mint_token(req, body.username)


@router.get("/me")
async def me(payload: dict = Depends(require_admin)):
    return {"username": payload.get("sub"), "expires_at": payload.get("exp")}
