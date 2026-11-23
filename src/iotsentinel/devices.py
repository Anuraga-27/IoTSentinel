"""The six virtual IoT devices and the network's normal-traffic profile."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Device:
    name: str
    ip: str
    mac: str
    kind: str   # "camera", "plug", "thermostat", "lock", "bulb", "assistant"


DEVICES: list[Device] = [
    Device("camera-1", "10.0.0.11", "AA:BB:CC:00:00:01", "camera"),
    Device("smart-plug-1", "10.0.0.12", "AA:BB:CC:00:00:02", "plug"),
    Device("thermostat-1", "10.0.0.13", "AA:BB:CC:00:00:03", "thermostat"),
    Device("door-lock-1", "10.0.0.14", "AA:BB:CC:00:00:04", "lock"),
    Device("smart-bulb-1", "10.0.0.15", "AA:BB:CC:00:00:05", "bulb"),
    Device("voice-assistant-1", "10.0.0.16", "AA:BB:CC:00:00:06", "assistant"),
]

CLOUD_IP = "203.0.113.10"   # where devices normally phone home
GATEWAY_IP = "10.0.0.1"

DEVICE_BY_NAME = {d.name: d for d in DEVICES}
DEVICE_BY_IP = {d.ip: d for d in DEVICES}
