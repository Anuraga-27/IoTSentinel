"""Measures pipeline throughput (records per second) under flood load.

Feeds a loud flood (800 packets/s for 300 simulated seconds = 240,000
records) through the full pipeline -- collector, rule engine, incident
grouper -- one record at a time, as the dashboard does. The SQLite store is
left out so the figure measures detection, not disk writes. Runs several
times and reports each run plus the slowest, which is the safe figure to
quote.

Usage:
    python validation/benchmark.py
    python validation/benchmark.py --seconds 600 --runs 5
"""

from __future__ import annotations

import argparse
import platform
import random
import time

import _bootstrap  # noqa: F401
from iotsentinel import attack_simulator as atk
from iotsentinel.pipeline import Pipeline, load_rules


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=300, help="simulated flood length")
    parser.add_argument("--pps", type=int, default=800, help="flood packets per second")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    config = load_rules()
    records = list(atk.flooding(args.seconds, 0.0, "camera-1", pps=args.pps,
                                rng=random.Random(1)))
    print(f"{len(records):,} flood records, {platform.python_version()} on "
          f"{platform.processor() or platform.machine()}")

    rates = []
    for run in range(1, args.runs + 1):
        pipeline = Pipeline(config)
        t0 = time.perf_counter()
        for rec in records:
            pipeline.process_record(rec)
        elapsed = time.perf_counter() - t0
        rates.append(len(records) / elapsed)
        print(f"  run {run}: {rates[-1]:,.0f} records/s  "
              f"({len(pipeline.incidents)} incident(s), {pipeline.violations_seen:,} violations)")

    print(f"Slowest run: {min(rates):,.0f} records/s")


if __name__ == "__main__":
    main()
