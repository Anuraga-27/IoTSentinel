"""Produces traffic for the five attacks, one generator per attack.

Each attack has a "loud" variant (clearly over threshold, used for the demo
and for confirming detection works) and a "slow"/stealthy variant that stays
under the configured thresholds, used by the validation harness to show
where the rule-based approach's detection boundary actually is.
"""

from __future__ import annotations

import random
from typing import Iterator

from .devices import DEVICES, DEVICE_BY_NAME
from .models import TrafficRecord

ATTACKER_IP = "198.51.100.50"
ATTACKER_MAC = "DE:AD:BE:EF:00:01"


def _target(device_name: str | None):
    if device_name:
        return DEVICE_BY_NAME[device_name]
    return random.choice(DEVICES)


def flooding(duration_s: float, start_time: float, device_name: str | None = None,
             pps: int = 800, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Loud variant: pps well above the 500/10s rule by default."""
    rng = rng or random.Random()
    target = _target(device_name)
    n = int(pps * duration_s)
    for i in range(n):
        t = start_time + (i / pps) + rng.uniform(-0.001, 0.001)
        yield TrafficRecord(
            timestamp=t, src_ip=ATTACKER_IP, src_mac=ATTACKER_MAC,
            dst_ip=target.ip, dst_device=target.name, dst_port=target_port_for_flood(),
            protocol="tcp", event="packet", size_bytes=rng.randint(40, 100),
            label="flooding",
        )


def target_port_for_flood() -> int:
    return 80


def flooding_slow(duration_s: float, start_time: float, device_name: str | None = None,
                   pps: int = 40, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Stealthy variant: pps kept below the 500/10s threshold (low-rate DoS)."""
    yield from flooding(duration_s, start_time, device_name, pps=pps, rng=rng)


def port_scan(duration_s: float, start_time: float, device_name: str | None = None,
              ports_per_second: int = 10, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Loud variant: well above 20 distinct ports / 10s."""
    rng = rng or random.Random()
    target = _target(device_name)
    t = start_time
    port = 1
    end = start_time + duration_s
    while t < end:
        yield TrafficRecord(
            timestamp=t, src_ip=ATTACKER_IP, src_mac=ATTACKER_MAC,
            dst_ip=target.ip, dst_device=target.name, dst_port=port,
            protocol="tcp", event="packet", size_bytes=40,
            label="port_scan",
        )
        port += 1
        t += 1.0 / ports_per_second


def port_scan_slow(duration_s: float, start_time: float, device_name: str | None = None,
                    seconds_per_port: float = 2.0, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Stealthy variant: ~1 new port every 2s, i.e. ~5 distinct ports per
    10s window -- under the 20/10s threshold."""
    rng = rng or random.Random()
    target = _target(device_name)
    t = start_time
    port = 1
    end = start_time + duration_s
    while t < end:
        yield TrafficRecord(
            timestamp=t, src_ip=ATTACKER_IP, src_mac=ATTACKER_MAC,
            dst_ip=target.ip, dst_device=target.name, dst_port=port,
            protocol="tcp", event="packet", size_bytes=40,
            label="port_scan",
        )
        port += 1
        t += seconds_per_port


def brute_force(duration_s: float, start_time: float, device_name: str | None = None,
                 attempts_per_minute: int = 30, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Loud variant: well above 5 failed logins / 60s."""
    rng = rng or random.Random()
    target = _target(device_name)
    interval = 60.0 / attempts_per_minute
    t = start_time
    end = start_time + duration_s
    while t < end:
        yield TrafficRecord(
            timestamp=t, src_ip=ATTACKER_IP, src_mac=ATTACKER_MAC,
            dst_ip=target.ip, dst_device=target.name, dst_port=22,
            protocol="tcp", event="login_failed", size_bytes=64,
            label="brute_force",
        )
        t += interval


def brute_force_slow(duration_s: float, start_time: float, device_name: str | None = None,
                      attempts_per_minute: int = 4, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Stealthy variant: ~4 failed logins/minute, under the 5/60s threshold."""
    yield from brute_force(duration_s, start_time, device_name, attempts_per_minute, rng)


def arp_spoof(duration_s: float = 1.0, start_time: float = 0.0, device_name: str | None = None,
              rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """The attacker claims a victim device's IP with its own MAC, while the
    real device keeps announcing its genuine MAC for the same IP. This
    contention -- two identities claiming one IP at once -- is what
    distinguishes real ARP spoofing from a harmless DHCP reassignment
    (where the old MAC simply stops appearing), and is what the rule
    engine's grace period is designed to catch."""
    target = _target(device_name)
    yield TrafficRecord(
        timestamp=start_time, src_ip=target.ip, src_mac=ATTACKER_MAC,
        dst_ip=target.ip, dst_device=target.name, dst_port=0,
        protocol="arp", event="arp_announce", size_bytes=42,
        label="arp_spoof",
    )
    yield TrafficRecord(
        timestamp=start_time + 1.0, src_ip=target.ip, src_mac=target.mac,
        dst_ip=target.ip, dst_device=target.name, dst_port=0,
        protocol="arp", event="arp_announce", size_bytes=42,
        label="arp_spoof",
    )


def botnet(duration_s: float, start_time: float, device_name: str | None = None,
           connections_per_30s: int = 25, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Loud variant: an infected device making telnet connections to many
    distinct external hosts -- well above 10/30s."""
    rng = rng or random.Random()
    source = _target(device_name)
    t = start_time
    end = start_time + duration_s
    host_idx = 0
    interval = 30.0 / connections_per_30s
    while t < end:
        host_idx += 1
        yield TrafficRecord(
            timestamp=t, src_ip=source.ip, src_mac=source.mac,
            dst_ip=f"203.0.113.{100 + (host_idx % 150)}", dst_device=source.name,
            dst_port=23, protocol="telnet", event="connect", size_bytes=60,
            label="botnet",
        )
        t += interval


def botnet_slow(duration_s: float, start_time: float, device_name: str | None = None,
                 connections_per_30s: int = 4, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Stealthy variant: ~4 distinct telnet hosts per 30s, under threshold."""
    yield from botnet(duration_s, start_time, device_name, connections_per_30s, rng)


ATTACKS = {
    "flooding": flooding,
    "port_scan": port_scan,
    "brute_force": brute_force,
    "arp_spoof": arp_spoof,
    "botnet": botnet,
}

SLOW_ATTACKS = {
    "flooding": flooding_slow,
    "port_scan": port_scan_slow,
    "brute_force": brute_force_slow,
    "arp_spoof": arp_spoof,   # a single forged frame has no "slow" variant
    "botnet": botnet_slow,
}
