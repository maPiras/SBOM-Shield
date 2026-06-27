#!/usr/bin/env python3
"""
SBOM-Shield API server.

Run:
    uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload

Or directly:
    python api/server.py
"""
import asyncio
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from storage.database import (
    create_track,
    delete_track,
    disable_track,
    get_conn,
    get_kev_active,
    get_recent_scans,
    get_scan_detail,
    get_severity_breakdown,
    get_sources_stats,
    get_summary,
    get_track,
    get_track_history,
    get_trend,
    init_db,
    list_tracks,
    save_scan,
    search_scans,
    upgrade_track_version,
)

# ─── JWT config ───────────────────────────────────────────────────────────────

SECRET_KEY         = os.getenv("SBOMSHIELD_SECRET", "sbomshield-dev-secret-change-in-prod")
# Base directory that contains cloned repositories (one subdir per repo)
REPOS_BASE         = Path(os.getenv("SBOMSHIELD_REPOS_DIR", str(Path.home() / "repos")))
ALGORITHM          = "HS256"
ACCESS_TOKEN_TTL   = 3600       # 1 h
REFRESH_TOKEN_TTL  = 86400 * 7  # 7 days

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="SBOM-Shield API", docs_url="/api/docs", redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_bearer = HTTPBearer(auto_error=False)

# scan_id -> queue.Queue  (active SSE streams)
_scan_queues: dict[str, queue.Queue] = {}

# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _make_token(payload: dict, ttl: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    return jwt.encode({**payload, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def _get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    if not creds:
        raise HTTPException(401, "Not authenticated")
    try:
        payload = _decode_token(creds.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, is_admin FROM users WHERE id = ?", (int(payload["sub"]),)
        ).fetchone()
    if not row:
        raise HTTPException(401, "User not found")
    return dict(row)

# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.post("/api/v1/auth/login")
async def login(request: Request):
    body     = await request.json()
    email    = (body.get("email", "") or "").strip().lower()
    password = body.get("password", "") or ""

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, is_admin FROM users WHERE email = ?", (email,)
        ).fetchone()

    if not row or not bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(401, "Invalid credentials")

    payload = {"sub": str(row["id"]), "email": row["email"], "is_admin": bool(row["is_admin"])}
    return {
        "access_token":  _make_token(payload, ACCESS_TOKEN_TTL),
        "refresh_token": _make_token(payload, REFRESH_TOKEN_TTL),
    }


@app.get("/api/v1/auth/me")
def me(user: dict = Depends(_get_current_user)):
    return {"email": user["email"], "is_admin": bool(user["is_admin"])}

# ─── Dashboard routes ─────────────────────────────────────────────────────────

@app.get("/api/pipeline/summary")
def pipeline_summary(user: dict = Depends(_get_current_user)):
    return get_summary()


@app.get("/api/scans/recent")
def recent_scans(limit: int = 6, user: dict = Depends(_get_current_user)):
    return get_recent_scans(limit)


@app.get("/api/vulns/severity-breakdown")
def severity_breakdown(user: dict = Depends(_get_current_user)):
    return get_severity_breakdown()


@app.get("/api/sources/stats")
def sources_stats(user: dict = Depends(_get_current_user)):
    return get_sources_stats()


@app.get("/api/vulns/trend")
def vulns_trend(days: int = 7, user: dict = Depends(_get_current_user)):
    return get_trend(days)


@app.get("/api/kev/active")
def kev_active(user: dict = Depends(_get_current_user)):
    return get_kev_active()


@app.get("/api/scans/search")
def scans_search(q: str = "", limit: int = 50, user: dict = Depends(_get_current_user)):
    return search_scans(q, limit)


@app.get("/api/scans/{scan_id}/detail")
def scan_detail(scan_id: int, user: dict = Depends(_get_current_user)):
    detail = get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(404, "Scan not found")
    return detail

# ─── Repos listing ────────────────────────────────────────────────────────────

@app.get("/api/repos")
def list_repos(user: dict = Depends(_get_current_user)):
    """Return names of directories under REPOS_BASE."""
    if not REPOS_BASE.exists():
        return []
    return sorted(
        p.name for p in REPOS_BASE.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )


# ─── Scan runner ──────────────────────────────────────────────────────────────

@app.post("/api/scan/run")
async def run_scan(request: Request, user: dict = Depends(_get_current_user)):
    body              = await request.json()
    run_ec            = bool(body.get("extended_coverage", True))
    include_indirect  = bool(body.get("include_indirect",  False))
    syft_fallback     = bool(body.get("syft_fallback",     True))
    online_resolution = bool(body.get("online_resolution", False))
    version           = (body.get("version", "") or "").strip() or None
    context_profile   = body.get("context_profile")  # dict | preset name | None

    # Accept either an absolute repo_path or a repo_name relative to REPOS_BASE
    repo_name = (body.get("repo_name", "") or "").strip()
    repo_path = (body.get("repo_path", "") or "").strip()
    if repo_name and not repo_path:
        repo_path = str(REPOS_BASE / repo_name)

    if not repo_path:
        raise HTTPException(400, "repo_name or repo_path is required")
    if not Path(repo_path).exists():
        raise HTTPException(400, f"Path not found: {repo_path}")

    scan_id                = str(uuid.uuid4())
    q: queue.Queue         = queue.Queue()
    _scan_queues[scan_id]  = q

    pipeline_opts = {
        "extended_coverage": run_ec,
        "include_indirect":  include_indirect,
        "syft_fallback":     syft_fallback,
        "online_resolution": online_resolution,
    }

    def _worker():
        def emit(stage: str, pct: int, done: bool = False, error: bool = False):
            q.put(json.dumps({"stage": stage, "pct": pct, "done": done, "error": error}))

        try:
            from core.pipeline import run_pipeline
            report = run_pipeline(
                repo_path=repo_path,
                version=version,
                context_profile=context_profile,
                track_id=None,
                options=pipeline_opts,
                emit=emit,
            )

            emit("Writing report...", 96)
            from core.report_generator import save_report as file_save
            out_dir = ROOT / "reports"
            out_dir.mkdir(exist_ok=True)
            file_save(report, out_dir / f"security_report_{scan_id}.json")
            file_save(report, out_dir / "security_report.json")
            save_scan(report)
            emit("Scan complete.", 100, done=True)

        except Exception as exc:
            emit(f"Error: {exc}", 0, done=True, error=True)
        finally:
            # keep queue alive for 60 s so late consumers can drain
            import time; time.sleep(60)
            _scan_queues.pop(scan_id, None)

    threading.Thread(target=_worker, daemon=True).start()
    return {"scan_id": scan_id}


# ─── Tracking endpoints ───────────────────────────────────────────────────────

@app.get("/api/tracks")
def tracks_list(user: dict = Depends(_get_current_user)):
    return list_tracks()


@app.get("/api/tracks/{track_id}")
def tracks_get(track_id: int, user: dict = Depends(_get_current_user)):
    t = get_track(track_id)
    if not t:
        raise HTTPException(404, "Track not found")
    t["history"] = get_track_history(track_id)
    return t


@app.post("/api/tracks")
async def tracks_create(request: Request, user: dict = Depends(_get_current_user)):
    """Create a new track. Body identical to /api/scan/run except a new
    `interval_hours` field (default 24). Performs the first scan synchronously
    in a background thread and returns immediately with the new track id."""
    body            = await request.json()
    project_name    = (body.get("project_name") or body.get("repo_name") or "").strip()
    repo_name       = (body.get("repo_name", "") or "").strip()
    repo_path       = (body.get("repo_path", "") or "").strip()
    version         = (body.get("version",   "") or "").strip()
    interval_hours  = int(body.get("interval_hours", 24))
    context_profile = body.get("context_profile") or "production_ot"

    if repo_name and not repo_path:
        repo_path = str(REPOS_BASE / repo_name)
    if not project_name:
        project_name = repo_name or Path(repo_path).name

    if not repo_path:
        raise HTTPException(400, "repo_name or repo_path is required")
    if not Path(repo_path).exists():
        raise HTTPException(400, f"Path not found: {repo_path}")
    if not version:
        raise HTTPException(400, "version is required")
    if interval_hours < 1 or interval_hours > 24 * 30:
        raise HTTPException(400, "interval_hours must be between 1 and 720")

    # Normalise the context profile to a dict so it can be serialised as-is
    from core.priority import load_profile
    profile_obj = load_profile(context_profile)

    options = {
        "extended_coverage": bool(body.get("extended_coverage", True)),
        "include_indirect":  bool(body.get("include_indirect",  False)),
        "syft_fallback":     bool(body.get("syft_fallback",     True)),
        "online_resolution": bool(body.get("online_resolution", False)),
    }

    track_id = create_track(
        project_name=project_name,
        repo_path=repo_path,
        current_version=version,
        context_profile=profile_obj.to_jsonable(),
        interval_hours=interval_hours,
        options=options,
    )

    # Kick off the first scan in the background — don't block the HTTP response
    def _initial():
        from core.tracking import run_track_now
        run_track_now(track_id)

    threading.Thread(target=_initial, name=f"track-init-{track_id}", daemon=True).start()
    return {"track_id": track_id}


@app.post("/api/tracks/{track_id}/upgrade")
async def tracks_upgrade(track_id: int, request: Request, user: dict = Depends(_get_current_user)):
    """Move the track pointer to a new version. Previous scans remain linked
    (track_id stays) so the timeline preserves history. Triggers an immediate
    scan of the new version."""
    body        = await request.json()
    new_version = (body.get("version", "") or "").strip()
    if not new_version:
        raise HTTPException(400, "version is required")

    if not get_track(track_id):
        raise HTTPException(404, "Track not found")

    upgrade_track_version(track_id, new_version)

    def _rescan():
        from core.tracking import run_track_now
        run_track_now(track_id)

    threading.Thread(target=_rescan, name=f"track-upgrade-{track_id}", daemon=True).start()
    return {"track_id": track_id, "version": new_version, "status": "rescan_started"}


@app.post("/api/tracks/{track_id}/disable")
def tracks_disable(track_id: int, user: dict = Depends(_get_current_user)):
    if not get_track(track_id):
        raise HTTPException(404, "Track not found")
    disable_track(track_id)
    return {"track_id": track_id, "enabled": False}


@app.delete("/api/tracks/{track_id}")
def tracks_delete(track_id: int, user: dict = Depends(_get_current_user)):
    if not get_track(track_id):
        raise HTTPException(404, "Track not found")
    delete_track(track_id)
    return {"track_id": track_id, "deleted": True}


@app.get("/api/priority/presets")
def priority_presets(user: dict = Depends(_get_current_user)):
    """Expose the built-in ContextProfile presets so the GUI can populate the
    preset dropdown without hard-coding the list."""
    from core.priority import PRESETS, DEFAULT_PRESET
    return {
        "default": DEFAULT_PRESET,
        "presets": {k: v.to_jsonable() for k, v in PRESETS.items()},
    }


@app.get("/api/scan/stream/{scan_id}")
async def scan_stream(scan_id: str, token: str = ""):
    """SSE endpoint. Token passed as query param because EventSource can't set headers."""
    try:
        _decode_token(token)
    except Exception:
        raise HTTPException(401, "Invalid token")

    if scan_id not in _scan_queues:
        raise HTTPException(404, "Scan not found or already expired")

    q = _scan_queues[scan_id]

    async def _event_gen():
        loop = asyncio.get_event_loop()
        while True:
            try:
                msg = await loop.run_in_executor(None, lambda: q.get(timeout=120))
                yield f"data: {msg}\n\n"
                if json.loads(msg).get("done"):
                    break
            except Exception:
                break

    return StreamingResponse(
        _event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# ─── extended_coverage endpoint ────────────────────────────────────────────────────────

@app.post("/api/ot/analyze")
async def ot_analyze(request: Request, user: dict = Depends(_get_current_user)):
    """
    Run the OT/ICS static-analysis layer on an arbitrary local path without
    triggering a full SBOM + vulnerability scan.

    Body: { "repo_path": "/absolute/path" }
    """
    body      = await request.json()
    repo_path = (body.get("repo_path", "") or "").strip()

    if not repo_path:
        raise HTTPException(400, "repo_path is required")
    if not Path(repo_path).exists():
        raise HTTPException(400, f"Path not found: {repo_path}")

    from core.extended_coverage import run as ec_run
    result = ec_run(repo_path)
    return result.to_dict()


# ─── Startup + static files ───────────────────────────────────────────────────

@app.on_event("startup")
async def _startup():
    init_db()
    from core.tracking import start_scheduler
    start_scheduler()


@app.on_event("shutdown")
async def _shutdown():
    from core.tracking import stop_scheduler
    stop_scheduler()


STATIC_DIR = ROOT / "dashboard" / "public"
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

# ─── Dev entry point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
