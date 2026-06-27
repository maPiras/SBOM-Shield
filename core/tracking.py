"""
Tracking scheduler — periodic vuln re-check for projects placed under tracking.

A "track" is a (project, version, context_profile, interval_hours) tuple stored
in the `tracks` table. The scheduler thread wakes every POLL_INTERVAL_SECONDS,
finds tracks whose `last_check_at + interval_hours` has elapsed, and re-runs
the full pipeline. Each re-run produces a new row in `scans` linked back to
the track via `scans.track_id`, so history is preserved automatically.

Version upgrade semantics
-------------------------
* The track's current_version pointer is updated on POST /api/tracks/{id}/upgrade.
* Old scans for previous versions stay attached to the track (same track_id)
  — querying `scans WHERE track_id = X ORDER BY generated_at` reconstructs the
  full multi-version timeline shown in the GUI.

Failure handling
----------------
* The scheduler catches every exception per-track so one bad repo doesn't stop
  the loop. Failed scans bump last_check_at anyway, so a permanently broken
  track does not get retried every poll cycle — it waits a full interval.
* The thread is daemonised; FastAPI shutdown reclaims it without a join.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from storage.database import (
    get_due_tracks,
    get_track,
    save_scan,
    update_track_after_scan,
)

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 300   # 5 minutes; tracks have hour granularity
_thread: Optional[threading.Thread] = None
_stop   = threading.Event()


def _run_one(track: dict) -> None:
    from core.pipeline import run_pipeline

    project = track["project_name"]
    logger.info(f"[tracking] running scheduled scan for track #{track['id']} ({project})")

    try:
        report = run_pipeline(
            repo_path=track["repo_path"],
            version=track["current_version"],
            context_profile=track["context_profile"],
            track_id=track["id"],
            options=track.get("options") or {},
            emit=None,
        )
    except Exception as exc:
        logger.warning(f"[tracking] track #{track['id']} pipeline failed: {exc}")
        # Bump last_check_at so we don't hammer a broken target every poll.
        update_track_after_scan(track["id"], scan_id=0)
        return

    try:
        scan_id = save_scan(report)
    except Exception as exc:
        logger.error(f"[tracking] track #{track['id']} save_scan failed: {exc}")
        update_track_after_scan(track["id"], scan_id=0)
        return

    update_track_after_scan(track["id"], scan_id=scan_id)
    pri = report.get("priority", {}).get("buckets", {})
    logger.info(
        f"[tracking] track #{track['id']} scan_id={scan_id} "
        f"Act={pri.get('Act', 0)} Attend={pri.get('Attend', 0)} "
        f"Track*={pri.get('Track*', 0)} Track={pri.get('Track', 0)}"
    )


def _loop() -> None:
    logger.info(f"[tracking] scheduler started (poll every {POLL_INTERVAL_SECONDS}s)")
    while not _stop.is_set():
        try:
            due = get_due_tracks(datetime.now(timezone.utc))
            for t in due:
                if _stop.is_set():
                    break
                _run_one(t)
        except Exception as exc:
            logger.error(f"[tracking] poll iteration failed: {exc}")
        _stop.wait(POLL_INTERVAL_SECONDS)


def start_scheduler() -> None:
    """Start the background poller if not already running. Idempotent."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="track-scheduler", daemon=True)
    _thread.start()


def stop_scheduler() -> None:
    _stop.set()


def run_track_now(track_id: int) -> Optional[int]:
    """Synchronously run the pipeline for a single track. Returns the new
    scan_id, or None on failure. Used by the API to do an immediate first
    scan when a track is created or when the version is upgraded."""
    track = get_track(track_id)
    if not track:
        return None

    from core.pipeline import run_pipeline
    try:
        report = run_pipeline(
            repo_path=track["repo_path"],
            version=track["current_version"],
            context_profile=track["context_profile"],
            track_id=track["id"],
            options=track.get("options") or {},
            emit=None,
        )
    except Exception as exc:
        logger.warning(f"[tracking] immediate scan for track #{track_id} failed: {exc}")
        return None

    scan_id = save_scan(report)
    update_track_after_scan(track_id, scan_id=scan_id)
    return scan_id
