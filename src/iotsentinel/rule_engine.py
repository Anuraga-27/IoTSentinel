"""Sliding-window rule engine: five detection rules, ARP grace period /
whitelist to cut noise, and incident grouping with severity escalation.
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from .models import TrafficRecord


@dataclass
class Violation:
    timestamp: float
    rule: str
    source: str
    target: str
    value: float
    threshold: float
    severity: str
    detail: str = ""


@dataclass
class Incident:
    """A group of repeated violations of the same rule/source/target."""
    rule: str
    source: str
    target: str
    severity: str
    first_seen: float
    last_seen: float
    count: int = 1
    base_severity: str = "medium"
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def key(self):
        return (self.rule, self.source, self.target)


class _SlidingCounter:
    """Counts timestamped events within a trailing window."""

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: deque[float] = deque()

    def add(self, t: float) -> int:
        self._events.append(t)
        self._evict(t)
        return len(self._events)

    def _evict(self, now: float) -> None:
        while self._events and now - self._events[0] > self.window:
            self._events.popleft()


class _SlidingTalkerCounter:
    """Counts events in a trailing window and tracks the top sender, so a
    flood is attributed to whoever is actually sending most of it."""

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: deque[tuple[float, str]] = deque()
        self._by_source: Counter[str] = Counter()

    def add(self, t: float, source: str) -> int:
        self._events.append((t, source))
        self._by_source[source] += 1
        while self._events and t - self._events[0][0] > self.window:
            _, old = self._events.popleft()
            self._by_source[old] -= 1
            if self._by_source[old] == 0:
                del self._by_source[old]
        return len(self._events)

    def top_source(self) -> str:
        return self._by_source.most_common(1)[0][0]


class _SlidingDistinctCounter:
    """Counts distinct values seen within a trailing window."""

    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._events: deque[tuple[float, object]] = deque()
        self._counts: Counter = Counter()

    def add(self, t: float, value: object) -> int:
        self._events.append((t, value))
        self._counts[value] += 1
        self._evict(t)
        return len(self._counts)

    def _evict(self, now: float) -> None:
        while self._events and now - self._events[0][0] > self.window:
            _, old = self._events.popleft()
            self._counts[old] -= 1
            if self._counts[old] == 0:
                del self._counts[old]


class ArpTracker:
    """Tracks IP->MAC bindings with a grace period and a whitelist, so a
    single DHCP reassignment does not raise an alert but genuine binding
    contention (two MACs claiming the same IP at once) still does."""

    def __init__(self, grace_period_seconds: float, whitelist: list[dict]):
        self.grace = grace_period_seconds
        self.whitelist = {(w["ip"], w["mac"]) for w in whitelist}
        self._binding: dict[str, str] = {}
        self._pending: dict[str, dict] = {}

    def observe(self, t: float, ip: str, mac: str) -> Optional[Violation]:
        if (ip, mac) in self.whitelist:
            self._binding[ip] = mac
            self._pending.pop(ip, None)
            return None

        current = self._binding.get(ip)
        if current is None:
            # first sighting of this IP -- nothing to compare against yet.
            self._binding[ip] = mac
            return None

        pending = self._pending.get(ip)
        if pending is None:
            if mac == current:
                return None
            # a new MAC for a known IP -- start the grace period, don't
            # alert yet (could be a legitimate DHCP reassignment).
            self._pending[ip] = {"new_mac": mac, "start": t}
            return None

        elapsed = t - pending["start"]

        if mac == pending["new_mac"]:
            if elapsed >= self.grace:
                self._binding[ip] = mac
                del self._pending[ip]
            return None

        if elapsed < self.grace:
            # A second identity (the original MAC reappearing, or a third
            # MAC) showed up WHILE the grace window was still open: two
            # identities contending for one IP at the same time -- the
            # real signature of ARP spoofing, as opposed to a clean
            # handover that simply never gets contested.
            self._pending[ip] = {"new_mac": mac, "start": t}
            return Violation(
                timestamp=t, rule="arp_spoof", source=ip, target=ip,
                value=1, threshold=0, severity="critical",
                detail=f"IP {ip} contended between MACs {current}/{pending['new_mac']} and {mac}",
            )

        # The grace window closed with no contender -- treat the pending
        # change as settled, then start tracking this new MAC as its own
        # (un-alerted) pending change.
        self._binding[ip] = pending["new_mac"]
        self._pending[ip] = {"new_mac": mac, "start": t}
        return None


class RuleEngine:
    def __init__(self, config: dict):
        r = config["rules"]
        self.flood_window = r["flooding"]["window_seconds"]
        self.flood_threshold = r["flooding"]["threshold"]
        self.scan_window = r["port_scan"]["window_seconds"]
        self.scan_threshold = r["port_scan"]["threshold"]
        self.scan_attempts_only = r["port_scan"].get("count_only_connection_attempts", False)
        self.brute_window = r["brute_force"]["window_seconds"]
        self.brute_threshold = r["brute_force"]["threshold"]
        self.botnet_window = r["botnet"]["window_seconds"]
        self.botnet_threshold = r["botnet"]["threshold"]

        self.arp = ArpTracker(
            r["arp_spoof"]["grace_period_seconds"],
            r["arp_spoof"].get("whitelist") or [],
        )

        self._flood_counters: dict[str, _SlidingTalkerCounter] = defaultdict(
            lambda: _SlidingTalkerCounter(self.flood_window))
        self._scan_counters: dict[str, _SlidingDistinctCounter] = defaultdict(
            lambda: _SlidingDistinctCounter(self.scan_window))
        self._brute_counters: dict[str, _SlidingCounter] = defaultdict(
            lambda: _SlidingCounter(self.brute_window))
        self._botnet_counters: dict[str, _SlidingDistinctCounter] = defaultdict(
            lambda: _SlidingDistinctCounter(self.botnet_window))

        self.severities = {name: cfg.get("severity", "medium") for name, cfg in r.items()}

    def ingest(self, rec: TrafficRecord) -> list[Violation]:
        violations: list[Violation] = []

        if rec.event == "packet":
            flood = self._flood_counters[rec.dst_device]
            n = flood.add(rec.timestamp, rec.src_ip)
            if n > self.flood_threshold:
                violations.append(Violation(
                    rec.timestamp, "flooding", flood.top_source(), rec.dst_device,
                    n, self.flood_threshold, self.severities["flooding"],
                    f"{n} packets in {self.flood_window}s",
                ))

            # Replies inside an open connection go to the client's random
            # ports and would look like a scan, so they can be left out.
            counts_for_scan = not (self.scan_attempts_only and rec.initiates is False)
            n = (self._scan_counters[rec.src_ip].add(rec.timestamp, rec.dst_port)
                 if counts_for_scan else 0)
            if n > self.scan_threshold:
                violations.append(Violation(
                    rec.timestamp, "port_scan", rec.src_ip, rec.dst_device,
                    n, self.scan_threshold, self.severities["port_scan"],
                    f"{n} distinct ports in {self.scan_window}s",
                ))

        if rec.event == "login_failed":
            n = self._brute_counters[rec.src_ip].add(rec.timestamp)
            if n > self.brute_threshold:
                violations.append(Violation(
                    rec.timestamp, "brute_force", rec.src_ip, rec.dst_device,
                    n, self.brute_threshold, self.severities["brute_force"],
                    f"{n} failed logins in {self.brute_window}s",
                ))

        if rec.protocol == "arp" and rec.event == "arp_announce":
            v = self.arp.observe(rec.timestamp, rec.dst_ip, rec.src_mac)
            if v is not None:
                v.target = rec.dst_device
                violations.append(v)

        if rec.protocol == "telnet" and rec.event == "connect":
            n = self._botnet_counters[rec.src_ip].add(rec.timestamp, rec.dst_ip)
            if n > self.botnet_threshold:
                violations.append(Violation(
                    rec.timestamp, "botnet", rec.src_ip, rec.dst_device,
                    n, self.botnet_threshold, self.severities["botnet"],
                    f"{n} distinct telnet targets in {self.botnet_window}s",
                ))

        return violations


class IncidentGrouper:
    """Folds repeated violations of the same (rule, source, target) into one
    incident within a trailing window, escalating severity on repeats
    instead of emitting one alert per threshold breach."""

    _ORDER = ["low", "medium", "high", "critical"]

    def __init__(self, group_window_seconds: float, escalation_repeat_counts: dict):
        self.window = group_window_seconds
        self.escalation = sorted(escalation_repeat_counts.items(), key=lambda kv: kv[1])
        self._open: dict[tuple, Incident] = {}

    def add(self, v: Violation) -> tuple[Incident, bool]:
        """Returns (incident, is_new_incident)."""
        key = (v.rule, v.source, v.target)
        existing = self._open.get(key)
        if existing is not None and v.timestamp - existing.last_seen <= self.window:
            existing.last_seen = v.timestamp
            existing.count += 1
            existing.severity = self._escalate(existing.base_severity, existing.count)
            return existing, False

        incident = Incident(
            rule=v.rule, source=v.source, target=v.target,
            severity=v.severity, base_severity=v.severity,
            first_seen=v.timestamp, last_seen=v.timestamp, count=1,
        )
        self._open[key] = incident
        return incident, True

    def _escalate(self, base: str, count: int) -> str:
        severity = base
        for level, repeats in self.escalation:
            if count >= repeats and self._rank(level) > self._rank(severity):
                severity = level
        return severity

    def _rank(self, level: str) -> int:
        return self._ORDER.index(level) if level in self._ORDER else 0
