"""Best-effort bridge from a CIC IoT 2023 CSV subset to IoTSentinel's raw
TrafficRecord events, so the rule engine can be scored against an external
dataset instead of only self-generated traffic.

IMPORTANT LIMITATION (read before trusting the numbers this produces):
The public CIC IoT 2023 release ships per-attack-category CSVs of
*already-aggregated flow features* (packet-rate, flag counts, protocol
one-hot columns, etc.) rather than raw per-packet events with real
source/destination ports and MAC addresses. IoTSentinel's rule engine
works on raw events (packets-per-second at a device, distinct ports from
a source, failed logins, ARP bindings, telnet fan-out). Those two
representations don't line up one-to-one.

This loader's approach: each CSV row is treated as one flow summary and is
expanded back into a short burst of synthetic raw events that reproduce the
row's rate/duration/protocol characteristics (e.g. a flow with a high
`Rate` and TCP flags becomes a packet burst at a device; a Telnet-heavy
flow becomes telnet connection events). The row's known category (taken
from the source filename, matching the dataset's own per-attack-category
files, e.g. `DDoS-TCP_Flood.csv`, `Recon-PortScan.csv`,
`DictionaryBruteForce.csv`, `MITM-ArpSpoofing.csv`,
`Mirai-greeting_flood.csv`, `BenignTraffic.csv`) is kept as ground truth.

Treat results from this path as indicative, not a certified benchmark:
they show whether the rule engine's thresholds are in the right ballpark
against real traffic statistics, not a packet-exact replay. Document this
caveat in the report alongside the numbers.
"""

from __future__ import annotations

import random
import re
from pathlib import Path

import pandas as pd

import _bootstrap  # noqa: F401
from iotsentinel import attack_simulator as atk
from iotsentinel.devices import DEVICES
from iotsentinel.models import TrafficRecord
from scenarios import GroundTruthWindow, EXPECTED_RULE

# Checked in order. Mirai comes before the flood pattern because the
# dataset names its botnet files like "Mirai-greeth_flood".
CATEGORY_FROM_FILENAME = [
    (re.compile(r"benign", re.I), "normal"),
    (re.compile(r"mirai|botnet|telnet", re.I), "botnet"),
    (re.compile(r"spoof|mitm|arp", re.I), "arp_spoof"),
    (re.compile(r"brute|dictionary", re.I), "brute_force"),
    (re.compile(r"recon|scan", re.I), "port_scan"),
    (re.compile(r"ddos|dos|flood", re.I), "flooding"),
]


def infer_category(path: str | Path) -> str:
    name = Path(path).name
    for pattern, category in CATEGORY_FROM_FILENAME:
        if pattern.search(name):
            return category
    raise ValueError(
        f"Could not infer attack category from filename '{name}'. "
        f"Rename it to match the dataset's own convention "
        f"(e.g. contains 'DDoS', 'Recon', 'Brute', 'Spoof', 'Mirai' or 'Benign'), "
        f"or pass --category explicitly."
    )


def _rate_of(row: pd.Series, default: float) -> float:
    for col in ("Rate", "Srate", "rate"):
        if col in row and pd.notna(row[col]) and row[col] > 0:
            return float(row[col])
    return default


def _number_of(row: pd.Series, default: int) -> int:
    for col in ("Number", "number"):
        if col in row and pd.notna(row[col]) and row[col] > 0:
            return max(1, int(row[col]))
    return default


def load_cic_csv(path: str | Path, category: str | None = None,
                  max_rows: int = 500, seed: int = 11, start_time: float = 2_000_000.0,
                  ) -> tuple[list[TrafficRecord], list[GroundTruthWindow]]:
    path = Path(path)
    category = category or infer_category(path)
    df = pd.read_csv(path, nrows=max_rows)

    rng = random.Random(seed)
    records: list[TrafficRecord] = []
    windows: list[GroundTruthWindow] = []
    t = start_time
    devices = list(DEVICES)

    for idx, row in df.iterrows():
        device = devices[idx % len(devices)]
        start = t
        if category == "normal":
            pps = min(5.0, _rate_of(row, 1.0))
            duration = 2.0
            for r in _normal_burst(start, duration, pps, device.name, rng):
                records.append(r)
            windows.append(GroundTruthWindow("normal", None, "cic", device.name,
                                              start, start + duration, detectable=False,
                                              note=f"CIC row {idx} ({path.name})"))
        else:
            source_ip = f"198.51.100.{100 + (idx % 150)}"
            gen_kwargs = _kwargs_for_category(category, row)
            recs = list(_synthesize_attack(category, start, device.name, source_ip,
                                            rng, **gen_kwargs))
            records.extend(recs)
            duration = gen_kwargs.get("duration_s", 1.0)
            windows.append(GroundTruthWindow(category, EXPECTED_RULE[category],
                                              source_ip, device.name,
                                              start, start + duration, detectable=True,
                                              note=f"CIC row {idx} ({path.name})"))
        t = start + 3.0  # small gap so windows don't bleed into each other

    records.sort(key=lambda r: r.timestamp)
    return records, windows


def _normal_burst(start, duration, pps, device_name, rng):
    device = next(d for d in DEVICES if d.name == device_name)
    n = max(1, int(pps * duration))
    for i in range(n):
        yield TrafficRecord(
            timestamp=start + i / max(pps, 1), src_ip=device.ip, src_mac=device.mac,
            dst_ip="203.0.113.10", dst_device=device.name, dst_port=443,
            protocol="tcp", event="packet", size_bytes=rng.randint(64, 512), label="normal",
        )


def _kwargs_for_category(category: str, row: pd.Series) -> dict:
    if category == "flooding":
        pps = max(50, min(2000, int(_rate_of(row, 800))))
        return {"pps": pps, "duration_s": 5.0}
    if category == "port_scan":
        n_ports = _number_of(row, 30)
        return {"ports_per_second": max(1, n_ports // 5), "duration_s": 5.0}
    if category == "brute_force":
        attempts = _number_of(row, 20)
        return {"attempts_per_minute": max(6, attempts), "duration_s": 60.0}
    if category == "botnet":
        n = _number_of(row, 20)
        return {"connections_per_30s": max(3, n), "duration_s": 30.0}
    return {}


def _synthesize_attack(category: str, start: float, device_name: str, source_ip: str,
                        rng: random.Random, **kwargs):
    if category == "arp_spoof":
        device = next(d for d in DEVICES if d.name == device_name)
        yield TrafficRecord(
            timestamp=start, src_ip=device.ip, src_mac="DE:AD:00:00:00:FF",
            dst_ip=device.ip, dst_device=device.name, dst_port=0,
            protocol="arp", event="arp_announce", size_bytes=42, label="arp_spoof",
        )
        # the real device keeps using its genuine MAC too -- this
        # contention is the signal the grace-period logic looks for.
        yield TrafficRecord(
            timestamp=start + 1.0, src_ip=device.ip, src_mac=device.mac,
            dst_ip=device.ip, dst_device=device.name, dst_port=0,
            protocol="arp", event="arp_announce", size_bytes=42, label="arp_spoof",
        )
        return

    gen_map = {"flooding": atk.flooding, "port_scan": atk.port_scan,
               "brute_force": atk.brute_force, "botnet": atk.botnet}
    gen = gen_map[category]
    for rec in gen(start_time=start, device_name=device_name, rng=rng, **kwargs):
        rec = TrafficRecord(**{**rec.__dict__, "src_ip": source_ip})
        yield rec
