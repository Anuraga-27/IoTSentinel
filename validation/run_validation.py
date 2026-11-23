"""Runs the labeled test corpus (and, optionally, a CIC IoT 2023 CSV subset)
through the real IoTSentinel pipeline and reports precision, recall and
false-positive rate per attack.

Usage:
    python validation/run_validation.py
    python validation/run_validation.py --cic-csv path\\to\\DDoS-TCP_Flood.csv
    python validation/run_validation.py --cic-csv a.csv --cic-csv b.csv --max-rows 300
"""

from __future__ import annotations

import argparse

import _bootstrap  # noqa: F401
from iotsentinel.pipeline import Pipeline, load_rules

import cic_loader
import metrics
from scenarios import build_corpus


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cic-csv", action="append", default=[],
                         help="Path to a CIC IoT 2023 per-category CSV (repeatable)")
    parser.add_argument("--max-rows", type=int, default=300)
    parser.add_argument("--rules", default=None, help="Path to an alternate rules.yaml")
    args = parser.parse_args()

    config = load_rules(args.rules) if args.rules else load_rules()

    records, windows = build_corpus()
    print(f"Self-generated corpus: {len(records)} records, {len(windows)} ground-truth windows\n")

    for n, csv_path in enumerate(args.cic_csv):
        # each file gets its own time slot so files never overlap on a device
        cic_records, cic_windows = cic_loader.load_cic_csv(
            csv_path, max_rows=args.max_rows, start_time=2_000_000.0 + n * 100_000.0)
        print(f"CIC subset {csv_path}: {len(cic_records)} records, "
              f"{len(cic_windows)} ground-truth windows")
        records.extend(cic_records)
        windows.extend(cic_windows)

    records.sort(key=lambda r: r.timestamp)

    pipeline = Pipeline(config)
    incidents = pipeline.process_stream(records)

    print(f"\nFlow collector: {pipeline.collector.stats()}")
    print(f"Raw rule violations: {pipeline.violations_seen}")
    print(f"Grouped incidents: {len(pipeline.incidents)}\n")

    result = metrics.score(windows, pipeline.incidents)
    metrics.print_report(result)

    print("\nNote: rows under 'detectable=False' (hard benign cases and "
          "slow/stealthy attacks) are EXPECTED to score as misses/false "
          "positives with fixed thresholds -- that is the point of including "
          "them. See validation/threshold_sweep.py for how detection trades "
          "off against false alarms as thresholds change.")


if __name__ == "__main__":
    main()
