"""CLI sub-command for TLS version detection."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from portmap.tls_version import TLSVersionResult, detect


def build_tls_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("tls", help="Detect TLS version on one or more ports")
    p.add_argument("ports", nargs="+", type=int, help="Port numbers to probe")
    p.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    p.add_argument("--deprecated-only", action="store_true", help="Show only deprecated TLS versions")
    return p


def _render_text(results: List[TLSVersionResult], deprecated_only: bool) -> None:
    shown = [r for r in results if not deprecated_only or r.deprecated]
    if not shown:
        print("No results.")
        return
    for r in shown:
        print(r.display())


def _render_json(results: List[TLSVersionResult], deprecated_only: bool) -> None:
    shown = [r for r in results if not deprecated_only or r.deprecated]
    out = [
        {
            "host": r.host,
            "port": r.port,
            "version": r.version,
            "cipher": r.cipher,
            "deprecated": r.deprecated,
        }
        for r in shown
    ]
    print(json.dumps(out, indent=2))


def run_tls(args: argparse.Namespace) -> None:
    results = [detect(args.host, p, timeout=args.timeout) for p in args.ports]
    if args.fmt == "json":
        _render_json(results, args.deprecated_only)
    else:
        _render_text(results, args.deprecated_only)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-tls")
    sub = parser.add_subparsers(dest="cmd")
    build_tls_parser(sub)
    args = parser.parse_args(argv)
    if args.cmd is None:
        parser.print_help()
        sys.exit(1)
    run_tls(args)
