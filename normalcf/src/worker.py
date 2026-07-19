"""FastAPI + D1 lab DB (defensive research: devices, jobs, artifacts, events)."""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from workers import WorkerEntrypoint

from lab import admin, artifacts, auth_routes, devices, events, jobs, misc
from lab.db import db

app = FastAPI(title="normalcf", docs_url="/docs", redoc_url=None)

# Allow admin-ui (Vite) and local tooling to call the lab API cross-origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(devices.router)
app.include_router(jobs.router)
app.include_router(artifacts.router)
app.include_router(events.router)
app.include_router(admin.router)
app.include_router(misc.public_router)
app.include_router(misc.router)


@app.get("/")
async def root():
    return {
        "ok": True,
        "service": "normalcf",
        "runtime": "fastapi",
        "db": "d1-lab",
        "console": "/console/",
        "group": "/group.html",
        "docs": "/docs",
    }


@app.get("/health")
async def health(req: Request):
    try:
        await db(req).prepare("SELECT 1 AS ok").first()
        return {"status": "healthy", "db": "ok"}
    except Exception as e:
        return {"status": "degraded", "db": str(e)}


@app.get("/hello/{name}")
async def hello(name: str):
    return {"message": f"hello, {name}"}


def _is_api_path(path: str) -> bool:
    """Paths handled by FastAPI (must win over static/ when run_worker_first)."""
    if path in ("/", "/health", "/openapi.json"):
        return True
    return (
        path.startswith("/lab")
        or path.startswith("/docs")
        or path.startswith("/hello/")
    )


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi
        import js

        js_req = request.js_object
        url = js.URL.new(js_req.url)
        path = url.pathname

        assets = getattr(self.env, "ASSETS", None)

        # Lab API + FastAPI built-ins
        if _is_api_path(path):
            return await asgi.fetch(app, js_req, self.env)

        if assets is None:
            return js.Response.new(
                "static assets missing",
                {
                    "status": 503,
                    "headers": {"content-type": "text/plain; charset=utf-8"},
                },
            )

        # Admin UI: Vite build lives in static/console, exposed at /console/*
        if path == "/console" or path.startswith("/console/"):
            asset_url = js.URL.new(js_req.url)
            # Keep /console prefix — assets root is static/, not static/console/
            if path == "/console":
                asset_url.pathname = "/console/"
            res = await assets.fetch(js.Request.new(asset_url.toString(), js_req))

            # SPA fallback for client routes (e.g. /console/devices)
            suffix = path[len("/console") :] or "/"
            if res.status == 404 and not suffix.startswith("/assets"):
                asset_url.pathname = "/console/index.html"
                res = await assets.fetch(js.Request.new(asset_url.toString(), js_req))
            return res

        # Everything else under static/ (group.html, *.js, downloaded/*, Stage*, …)
        return await assets.fetch(js_req)
