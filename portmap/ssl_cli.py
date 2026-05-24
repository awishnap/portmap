"""CLI sub-command: portmap ssl — inspect TLS certificates on open ports."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.scanner import scan_ports
from portmap.ssl_check import SSLResult, check


def build_ssl_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("ssl", help="Inspect TLS certificates on open ports")
    p.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p.add_argument("--ports", nargs="+", type=int, metavar="PORT", help="Explicit port list")
    p.add_argument("--timeout", type=float, default=3.0, help="Per-port timeout in seconds")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    p.add_argument("--only-ssl", action="store_true", help="Hide ports without SSL")
    p.add_argument("--warn-days", type=int, default=30, metavar="N",
                   help="Warn when certificate expires within N days (default: 30)")
    return p


def _render_text(results: List[SSLResult], only_ssl: bool, warn_days: int) -> None:
    if not results:
        print("No results.")
        return
    for r in results:
        if only_ssl and not r.has_ssl:
            continue
        line = r.display()
        if r.has_ssl and not r.error:
            if r.expired:
                line = f"[EXPIRED]  {line}"
            elif r.days_remaining is not None and r.days_remaining <= warn_days:
                line = f"[WARNING]  {line}"
            else:
                line = f"[OK]       {line}"
        print(line)


def _render_json(results: List[SSLResult], only_ssl: bool) -> None:
    out = []
    for r in results:
        if only_ssl and not r.has_ssl:
            continue
        out.append({
            "port": r.port,
            "host": r.host,
            "has_ssl": r.has_ssl,
            "subject": r.subject,
            "issuer": r.issuer,
            "expires": r.expires.isoformat() if r.expires else None,
            "expired": r.expired,
            "days_remaining": r.days_remaining,
            "error": r.error,
        })
    print(json.dumps(out, indent=2))


def run_ssl(args: argparse.Namespace) -> int:
    if args.ports:
        ports = args.ports
    else:
        entries = scan_ports()
        ports = [e.port for e in entries]

    results = [check(args.host, p, timeout=args.timeout) for p in ports]

    if args.fmt == "json":
        _render_json(results, args.only_ssl)
    else:
        _render_text(results, args.only_ssl, args.warn_days)
    return 0


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-ssl")
    sub = parser.add_subparsers(dest="cmd")
    build_ssl_parser(sub)
    args = parser.parse_args()
    sys.exit(run_ssl(args))
