"""Port trend analysis: track how port states change across multiple snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from portmap.snapshot import Snapshot


@dataclass
class PortTrend:
    port: int
    protocol: str
    appearances: int = 0
    disappearances: int = 0
    last_seen_label: Optional[str] = None
    last_seen_pid: Optional[int] = None
    snapshots_present: int = 0
    snapshots_total: int = 0

    @property
    def stability(self) -> float:
        """Fraction of snapshots where this port was open (0.0 – 1.0)."""
        if self.snapshots_total == 0:
            return 0.0
        return self.snapshots_present / self.snapshots_total

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass
class TrendReport:
    snapshots_analysed: int
    trends: List[PortTrend] = field(default_factory=list)

    def unstable(self, threshold: float = 0.8) -> List[PortTrend]:
        """Return ports whose stability is below *threshold*."""
        return [t for t in self.trends if t.stability < threshold]

    def always_open(self) -> List[PortTrend]:
        """Return ports that were open in every snapshot."""
        return [t for t in self.trends if t.stability == 1.0]


def analyse(snapshots: List[Snapshot]) -> TrendReport:
    """Compute per-port trends across an ordered list of snapshots."""
    if not snapshots:
        return TrendReport(snapshots_analysed=0)

    total = len(snapshots)
    trends: Dict[str, PortTrend] = {}
    prev_keys: set = set()

    for snapshot in snapshots:
        current_keys: set = set()

        for entry in snapshot.entries:
            key = f"{entry.port}/{entry.protocol}"
            current_keys.add(key)

            if key not in trends:
                trends[key] = PortTrend(
                    port=entry.port,
                    protocol=entry.protocol,
                    snapshots_total=total,
                )

            trend = trends[key]
            trend.snapshots_present += 1
            trend.last_seen_label = entry.label
            trend.last_seen_pid = entry.pid

            if key not in prev_keys:
                trend.appearances += 1

        for key in prev_keys - current_keys:
            if key in trends:
                trends[key].disappearances += 1

        prev_keys = current_keys

    return TrendReport(
        snapshots_analysed=total,
        trends=sorted(trends.values(), key=lambda t: (t.port, t.protocol)),
    )
