"""Format and print alert results to stdout or a file."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, TextIO

from portmap.alert import AlertResult


def render_text(results: List[AlertResult], stream: TextIO = sys.stdout) -> None:
    if not results:
        stream.write("No alerts triggered.\n")
        return
    for r in results:
        stream.write(str(r) + "\n")


def render_json(results: List[AlertResult], stream: TextIO = sys.stdout) -> None:
    payload = [
        {
            "rule": r.rule_name,
            "port": r.entry.port,
            "protocol": r.entry.protocol,
            "process": r.entry.process,
            "pid": r.entry.pid,
            "label": r.entry.label,
            "message": r.message,
        }
        for r in results
    ]
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def save_alerts(results: List[AlertResult], path: Path, fmt: str = "json") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        if fmt == "json":
            render_json(results, fh)
        else:
            render_text(results, fh)
