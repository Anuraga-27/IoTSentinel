"""Generates normal traffic for the six virtual IoT devices.

Also generates two "hard" benign scenarios the validation harness uses to
show where simple threshold rules strain: a firmware-update burst (looks
like a flood by packet rate) and a sustained camera stream (high volume,
single port, should NOT trip the port-scan or flood rule).
"""

from __future__ import annotations

import random
from typing import Iterator

from .devices import DEVICES, CLOUD_IP
from .models import TrafficRecord

# Roughly how often each device kind phones home, in seconds between packets.
BASELINE_INTERVAL_S = {
    "camera": 0.5,
    "plug": 4.0,
    "thermostat": 5.0,
    "lock": 6.0,
    "bulb": 4.0,
    "assistant": 2.0,
}

HEARTBEAT_PORT = 443


def normal_traffic(duration_s: float, start_time: float, jitter: float = 0.2,
                    rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Yield normal device<->cloud traffic for `duration_s` seconds, in time order."""
    rng = rng or random.Random()
    events: list[TrafficRecord] = []

    for device in DEVICES:
        interval = BASELINE_INTERVAL_S[device.kind]
        # establish the device's genuine IP/MAC binding once, near the
        # start, so a later spoofed binding has something legitimate to
        # contend with. Real devices don't re-announce ARP continuously,
        # so this is a single sighting, not a heartbeat.
        events.append(TrafficRecord(
            timestamp=start_time + rng.uniform(0, 1.0), src_ip=device.ip, src_mac=device.mac,
            dst_ip=device.ip, dst_device=device.name, dst_port=0,
            protocol="arp", event="arp_announce", size_bytes=42,
            label="normal",
        ))

        t = start_time
        while t < start_time + duration_s:
            events.append(TrafficRecord(
                timestamp=t,
                src_ip=device.ip,
                src_mac=device.mac,
                dst_ip=CLOUD_IP,
                dst_device=device.name,
                dst_port=HEARTBEAT_PORT,
                protocol="tcp",
                event="packet",
                size_bytes=rng.randint(64, 512),
                label="normal",
            ))
            # occasional legitimate login from the voice assistant app
            if device.kind == "assistant" and rng.random() < 0.05:
                events.append(TrafficRecord(
                    timestamp=t + interval / 2,
                    src_ip=device.ip,
                    src_mac=device.mac,
                    dst_ip=CLOUD_IP,
                    dst_device=device.name,
                    dst_port=22,
                    protocol="tcp",
                    event="login_ok",
                    label="normal",
                ))
            t += max(0.05, rng.gauss(interval, interval * jitter))

    events.sort(key=lambda r: r.timestamp)
    yield from events


def firmware_update_burst(duration_s: float, start_time: float,
                           device_name: str | None = None,
                           pps: int = 600,
                           rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """A legitimate but bursty firmware download: many packets arriving at
    one device in a short window. Hard benign case for the flooding rule
    (> threshold pps triggers it even though this is not an attack)."""
    rng = rng or random.Random()
    device = next(d for d in DEVICES if device_name in (None, d.name))
    n = int(pps * duration_s)
    for i in range(n):
        t = start_time + (i / pps) + rng.uniform(-0.001, 0.001)
        yield TrafficRecord(
            timestamp=t,
            src_ip=CLOUD_IP,
            src_mac="AA:BB:CC:FF:FF:FF",
            dst_ip=device.ip,
            dst_device=device.name,
            dst_port=HEARTBEAT_PORT,
            protocol="tcp",
            event="packet",
            size_bytes=1024,
            label="normal",
            meta={"scenario": "firmware_update_burst"},
        )


def dhcp_reassignment(start_time: float, device_name: str | None = None,
                       rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """A device legitimately renews its DHCP lease and starts announcing a
    new MAC for the same IP (e.g. after a NIC swap or router reboot). Hard
    benign case for the ARP-spoof rule -- a naive "any change" rule flags
    this as an attack; the grace period should let it settle silently."""
    rng = rng or random.Random()
    device = next(d for d in DEVICES if device_name in (None, d.name))
    new_mac = "AA:BB:CC:00:99:" + format(rng.randint(0, 255), "02X")
    yield TrafficRecord(
        timestamp=start_time, src_ip=device.ip, src_mac=new_mac,
        dst_ip=device.ip, dst_device=device.name, dst_port=0,
        protocol="arp", event="arp_announce", size_bytes=42,
        label="normal", meta={"scenario": "dhcp_reassignment"},
    )
    # the device keeps using its new MAC afterwards -- no contention, so
    # the rebinding should be accepted once the grace period elapses.
    for i in range(1, 6):
        yield TrafficRecord(
            timestamp=start_time + i * 5, src_ip=device.ip, src_mac=new_mac,
            dst_ip=device.ip, dst_device=device.name, dst_port=0,
            protocol="arp", event="arp_announce", size_bytes=42,
            label="normal", meta={"scenario": "dhcp_reassignment"},
        )


def camera_stream(duration_s: float, start_time: float,
                   pps: int = 60, rng: random.Random | None = None) -> Iterator[TrafficRecord]:
    """Sustained single-port, high-volume outgoing stream from the camera.
    Hard benign case for the port-scan rule (lots of traffic, but always the
    same destination port, so it must not be mistaken for scanning)."""
    rng = rng or random.Random()
    camera = next(d for d in DEVICES if d.kind == "camera")
    n = int(pps * duration_s)
    for i in range(n):
        t = start_time + (i / pps) + rng.uniform(-0.002, 0.002)
        yield TrafficRecord(
            timestamp=t,
            src_ip=camera.ip,
            src_mac=camera.mac,
            dst_ip=CLOUD_IP,
            dst_device=camera.name,
            dst_port=8554,  # fixed RTSP-ish port, every time
            protocol="tcp",
            event="packet",
            size_bytes=rng.randint(800, 1400),
            label="normal",
            meta={"scenario": "camera_stream"},
        )
