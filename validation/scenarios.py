"""Builds a labeled test corpus: normal traffic, hard benign cases, and all
five attacks in both loud (obvious) and slow/stealthy variants, each with a
known ground-truth window so detection can be scored against it.
"""

from __future__ import annotations

import _bootstrap  # noqa: F401
import random
from dataclasses import dataclass

from iotsentinel import attack_simulator as atk
from iotsentinel import device_simulator as dev
from iotsentinel.devices import DEVICES
from iotsentinel.models import TrafficRecord

EXPECTED_RULE = {
    "flooding": "flooding",
    "port_scan": "port_scan",
    "brute_force": "brute_force",
    "arp_spoof": "arp_spoof",
    "botnet": "botnet",
}


@dataclass
class GroundTruthWindow:
    label: str              # attack name, or "normal"
    expected_rule: str | None   # rule that SHOULD fire, or None for benign
    source: str
    target: str
    start: float
    end: float
    detectable: bool        # False for slow/stealthy variants kept under threshold
    note: str = ""


def build_corpus(seed: int = 7) -> tuple[list[TrafficRecord], list[GroundTruthWindow]]:
    rng = random.Random(seed)
    t = 1_000_000.0
    records: list[TrafficRecord] = []
    windows: list[GroundTruthWindow] = []

    def advance(gap: float) -> float:
        nonlocal t
        t += gap
        return t

    # --- baseline normal traffic running throughout ---
    baseline_start = t
    records += list(dev.normal_traffic(1200, baseline_start, rng=rng))

    # --- hard benign cases ---
    fw_start = advance(5)
    records += list(dev.firmware_update_burst(8, fw_start, device_name="thermostat-1", rng=rng))
    windows.append(GroundTruthWindow("normal", None, "cloud", "thermostat-1",
                                      fw_start, fw_start + 8, detectable=False,
                                      note="firmware_update_burst: legit but bursty, "
                                           "stresses the flooding rule's false-positive rate"))

    cam_start = advance(5)
    records += list(dev.camera_stream(20, cam_start, rng=rng))
    windows.append(GroundTruthWindow("normal", None, "camera-1", "camera-1",
                                      cam_start, cam_start + 20, detectable=False,
                                      note="camera_stream: single port (should not trip "
                                           "port_scan), but high enough volume to also "
                                           "stress the flooding rule's raw packet-count check"))

    dhcp_start = advance(5)
    records += list(dev.dhcp_reassignment(dhcp_start, device_name="smart-plug-1", rng=rng))
    windows.append(GroundTruthWindow("normal", None, "smart-plug-1", "smart-plug-1",
                                      dhcp_start, dhcp_start + 30, detectable=False,
                                      note="dhcp_reassignment: legit MAC change, "
                                           "must not fire without grace-period handling"))

    # --- loud attacks: one per rule, each on a distinct device ---
    loud_specs = [
        ("flooding", "camera-1", dict(duration_s=10)),
        ("port_scan", "door-lock-1", dict(duration_s=10)),
        ("brute_force", "voice-assistant-1", dict(duration_s=65)),
        ("arp_spoof", "smart-bulb-1", dict()),
        ("botnet", "thermostat-1", dict(duration_s=30)),
    ]
    for name, device_name, kwargs in loud_specs:
        start = advance(10)
        gen = atk.ATTACKS[name]
        duration = kwargs.get("duration_s", 1.0)
        recs = list(gen(start_time=start, device_name=device_name, rng=rng, **kwargs))
        records += recs
        source = recs[0].src_ip if recs else atk.ATTACKER_IP
        windows.append(GroundTruthWindow(name, EXPECTED_RULE[name], source, device_name,
                                          start, start + max(duration, 1.0), detectable=True,
                                          note="loud variant, clearly over threshold"))
        # let each attack finish and its rule windows drain before the next
        # one starts, so attacks from the same IP don't add up.
        advance(duration + 60)

    # --- slow / stealthy attacks: should mostly evade the fixed thresholds ---
    slow_specs = [
        ("flooding", "smart-plug-1", dict(duration_s=10)),
        ("port_scan", "camera-1", dict(duration_s=40)),
        ("brute_force", "door-lock-1", dict(duration_s=120)),
        ("botnet", "voice-assistant-1", dict(duration_s=90)),
    ]
    for name, device_name, kwargs in slow_specs:
        start = advance(10)
        gen = atk.SLOW_ATTACKS[name]
        duration = kwargs.get("duration_s", 1.0)
        recs = list(gen(start_time=start, device_name=device_name, rng=rng, **kwargs))
        records += recs
        source = recs[0].src_ip if recs else atk.ATTACKER_IP
        windows.append(GroundTruthWindow(name, EXPECTED_RULE[name], source, device_name,
                                          start, start + max(duration, 1.0), detectable=False,
                                          note="slow/stealthy variant, kept under threshold "
                                               "-- expected to be MISSED by fixed thresholds"))
        advance(duration + 60)

    records.sort(key=lambda r: r.timestamp)
    return records, windows
