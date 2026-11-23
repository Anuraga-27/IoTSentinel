"""Shared data model for traffic records flowing through IoTSentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrafficRecord:
    """One observed network event between a source and a device.

    `label` is ground truth used only for validation/scoring; the rule
    engine never reads it.
    """

    timestamp: float
    src_ip: str
    src_mac: str
    dst_ip: str
    dst_device: str
    dst_port: int
    protocol: str                 # "tcp", "udp", "telnet", "http", "arp"
    event: str                    # "packet", "login_failed", "login_ok", "arp_announce"
    size_bytes: int = 64
    label: str = "normal"         # "normal" or an attack name
    meta: dict = field(default_factory=dict)
    # True if this packet opens a connection (e.g. a TCP SYN), False if it is
    # part of one already open (e.g. a server's reply), None if unknown.
    initiates: Optional[bool] = None

    def is_malformed(self) -> bool:
        if not self.src_ip or not self.dst_ip or not self.dst_device:
            return True
        if self.dst_port is None or not (0 <= self.dst_port <= 65535):
            return True
        if self.timestamp is None or self.timestamp <= 0:
            return True
        return False
