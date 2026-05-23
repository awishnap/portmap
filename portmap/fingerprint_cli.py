"""CLI sub-command: portmap fingerprint — grab banners from open ports."""

from __future__ import annotations

import argparse
import json
import sys

from portmap.fingerprint import FingerprintResult, grab_banner
from portmap.scanner import scan_ports


def build_fingerprint_parser(sub: "argparse._SubParsersAction") -> argparse.ArgumentParser:  # type: ignore[type-arg]
    p = sub.add_parser("fingerprint", help="Grab service banners from open TCP ports")
    p.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    p.add_argument("--ports", default=None, help="Comma-separated port list (default: scan all)")
    p.add_argument("--timeout", type=float, default=2.0, help="Per-port socket timeout in seconds")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="fmt")
    return p


def _resolve_ports(ports_arg: str | None, host: str) -> list[int]:
    if ports_arg:
        return [int(p.strip()) for p in ports_arg.split(",") if p.strip()]
    entries = scan_ports()
    return [e.port for e in entries if e.protocol.lower() == "tcp"]


def _render_text(results: list[FingerprintResult]) -> None:
    for r in results:
        if r.error:
            print(f"  {r.port}/tcp  ERROR: {r.error}")
        else:
            hint = f" [{r.service_hint}]" if r.service_hint else ""
            banner_preview = (r.banner or "")[:60].replace("\n", " ")
            print(f"  {r.port}/tcp{hint}  {banner_preview}")


def _render_json(results: list[FingerprintResult]) -> None:
    out = [
        {
            "port": r.port,
            "protocol": r.protocol,
            "banner": r.banner,
            "service_hint": r.service_hint,
            "error": r.error,
        }
        for r in results
    ]
    print(json.dumps(out, indent=2))


def run_fingerprint(args: argparse.Namespace) -> int:
    ports = _resolve_ports(getattr(args, "ports", None), args.host)
    if not ports:
        print("No TCP ports to fingerprint.", file=sys.stderr)
        return 1

    results = [grab_banner(args.host, p, timeout=args.timeout) for p in ports]

    if args.fmt == "json":
        _render_json(results)
    else:
        print(f"Fingerprint results for {args.host}:")
        _render_text(results)
    return 0


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(prog="portmap-fingerprint")
    sub = parser.add_subparsers(dest="cmd")
    build_fingerprint_parser(sub)
    args = parser.parse_args()
    sys.exit(run_fingerprint(args))
