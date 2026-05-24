"""CLI helpers for inspecting and resetting the adaptive scan-rate controller."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from portmap.port_scan_rate import ScanRateController

_CONTROLLER: Optional[ScanRateController] = None


def _get_controller() -> ScanRateController:
    global _CONTROLLER
    if _CONTROLLER is None:
        _CONTROLLER = ScanRateController()
    return _CONTROLLER


def build_scan_rate_parser(sub: Optional[argparse._SubParsersAction] = None) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    kwargs = dict(description="Inspect or reset the adaptive scan-rate controller")
    p = sub.add_parser("scan-rate", **kwargs) if sub else argparse.ArgumentParser(**kwargs)
    cmds = p.add_subparsers(dest="cmd", required=True)

    cmds.add_parser("status", help="Show current worker recommendation and error rate")

    rec = cmds.add_parser("recommend", help="Trigger a recommendation cycle and print new worker count")
    rec.add_argument("--format", choices=["text", "json"], default="text")

    cmds.add_parser("reset", help="Reset counters and worker count to initial value")

    sim = cmds.add_parser("simulate", help="Record synthetic outcomes and recommend")
    sim.add_argument("--success", type=int, default=0, metavar="N")
    sim.add_argument("--error", type=int, default=0, metavar="N")
    sim.add_argument("--format", choices=["text", "json"], default="text")
    return p


def _render_status(ctrl: ScanRateController, fmt: str = "text") -> str:
    rate = ctrl.error_rate
    data = {
        "current_workers": ctrl.current_workers,
        "error_rate": round(rate, 4) if rate is not None else None,
        "target_error_rate": ctrl.target_error_rate,
    }
    if fmt == "json":
        return json.dumps(data, indent=2)
    rate_str = f"{rate:.2%}" if rate is not None else "n/a"
    return (f"workers={data['current_workers']}  "
            f"error_rate={rate_str}  "
            f"target={ctrl.target_error_rate:.0%}")


def run_scan_rate(args: argparse.Namespace, ctrl: Optional[ScanRateController] = None) -> int:
    c = ctrl or _get_controller()
    fmt = getattr(args, "format", "text")

    if args.cmd == "status":
        print(_render_status(c, fmt))
    elif args.cmd == "recommend":
        workers = c.recommend()
        if fmt == "json":
            print(json.dumps({"recommended_workers": workers}))
        else:
            print(f"recommended_workers={workers}")
    elif args.cmd == "reset":
        c.reset()
        print("Controller reset.")
    elif args.cmd == "simulate":
        for _ in range(args.success):
            c.record_success()
        for _ in range(args.error):
            c.record_error()
        workers = c.recommend()
        if fmt == "json":
            print(json.dumps({"recommended_workers": workers}))
        else:
            print(f"recommended_workers={workers}")
    return 0


def main(argv: Optional[List[str]] = None) -> None:
    p = build_scan_rate_parser()
    sys.exit(run_scan_rate(p.parse_args(argv)))


if __name__ == "__main__":
    main()
