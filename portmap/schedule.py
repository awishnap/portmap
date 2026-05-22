"""Scheduled scanning: run portmap scans at a fixed interval and persist snapshots."""

from __future__ import annotations

import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from portmap.snapshot import capture, save_snapshot
from portmap.snapshot_diff import compare
from portmap.alert import AlertRule, evaluate
from portmap.cache import write as cache_write

log = logging.getLogger(__name__)

DEFAULT_INTERVAL = 60  # seconds
DEFAULT_SNAPSHOT_DIR = Path(".portmap/scheduled")


def _snapshot_path(directory: Path, ts: datetime) -> Path:
    """Return a timestamped snapshot file path inside *directory*."""
    directory.mkdir(parents=True, exist_ok=True)
    filename = ts.strftime("snapshot_%Y%m%d_%H%M%S.json")
    return directory / filename


def run_once(
    ports: Optional[list[int]] = None,
    directory: Path = DEFAULT_SNAPSHOT_DIR,
    alert_rules: Optional[list[AlertRule]] = None,
    on_diff: Optional[Callable] = None,
) -> dict:
    """Capture a single snapshot, save it, and return a summary dict."""
    ts = datetime.utcnow()
    snap = capture(ports=ports)
    path = _snapshot_path(directory, ts)
    save_snapshot(snap, path)
    log.info("Snapshot saved to %s (%d entries)", path, len(snap.entries))

    summary: dict = {"timestamp": ts.isoformat(), "path": str(path), "alerts": []}

    if alert_rules:
        for entry in snap.entries:
            for rule in alert_rules:
                result = evaluate(rule, entry)
                if result.triggered:
                    summary["alerts"].append(str(result))
                    log.warning("ALERT: %s", result)

    if on_diff is not None:
        on_diff(snap)

    return summary


def run_loop(
    interval: int = DEFAULT_INTERVAL,
    ports: Optional[list[int]] = None,
    directory: Path = DEFAULT_SNAPSHOT_DIR,
    alert_rules: Optional[list[AlertRule]] = None,
    max_iterations: Optional[int] = None,
) -> None:
    """Run scans in a loop every *interval* seconds.

    Parameters
    ----------
    interval:        Seconds between scans.
    ports:           Port list to scan; ``None`` means all.
    directory:       Where to store snapshot JSON files.
    alert_rules:     Optional rules evaluated after each scan.
    max_iterations:  Stop after this many scans (``None`` = run forever).
    """
    log.info("Starting scheduled scan loop (interval=%ds)", interval)
    previous_snap = None
    iteration = 0

    while max_iterations is None or iteration < max_iterations:
        summary = run_once(ports=ports, directory=directory, alert_rules=alert_rules)

        # Diff against previous snapshot when available
        if previous_snap is not None:
            from portmap.snapshot import load_snapshot
            current_snap = load_snapshot(Path(summary["path"]))
            diff = compare(previous_snap, current_snap)
            if diff.has_changes():
                log.info("Changes detected: %s", diff.summary())
            previous_snap = current_snap
        else:
            from portmap.snapshot import load_snapshot
            previous_snap = load_snapshot(Path(summary["path"]))

        iteration += 1
        if max_iterations is None or iteration < max_iterations:
            time.sleep(interval)
