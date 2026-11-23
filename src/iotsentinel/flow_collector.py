"""Receives traffic records, validates them, and passes good ones on."""

from __future__ import annotations

from typing import Iterable, Iterator

from .models import TrafficRecord


class FlowCollector:
    def __init__(self) -> None:
        self.dropped = 0
        self.accepted = 0

    def process(self, records: Iterable[TrafficRecord]) -> Iterator[TrafficRecord]:
        for record in records:
            if record.is_malformed():
                self.dropped += 1
                continue
            self.accepted += 1
            yield record

    def stats(self) -> dict:
        return {"accepted": self.accepted, "dropped": self.dropped}
