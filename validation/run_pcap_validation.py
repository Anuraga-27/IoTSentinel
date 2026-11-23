"""Runs real packet captures from CIC IoT 2023 through the IoTSentinel
pipeline. Unlike the CSV path, nothing here is rebuilt by our own attack
scripts: the rules see the dataset's actual IPs, ports, MACs and timing.

Each file is labelled by its category (from the filename) and run through a
fresh pipeline. The report shows, per file, which rules fired, whether the
rule expected for that category fired, and how long after the first packet
it took. For the benign file, every incident is a false alarm.

Usage:
    python validation/run_pcap_validation.py D:\\CIC\\pcap
    python validation/run_pcap_validation.py file1.pcap file2.pcap --max-packets 200000
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

import _bootstrap  # noqa: F401
from iotsentinel.pipeline import Pipeline, load_rules

import pcap_loader
from cic_loader import infer_category
from scenarios import EXPECTED_RULE


def run_file(path: Path, config: dict, max_packets: int | None) -> dict:
    category = infer_category(path)
    expected = EXPECTED_RULE.get(category)
    pipeline = Pipeline(config)
    first_ts = last_ts = None
    packets = 0
    for rec in pcap_loader.read_pcap(path, label=category, max_packets=max_packets):
        if first_ts is None:
            first_ts = rec.timestamp
        last_ts = rec.timestamp
        if rec.event == "packet":
            packets += 1
        pipeline.process_record(rec)

    incidents = pipeline.incidents
    by_rule = Counter(i.rule for i in incidents)
    hit = [i for i in incidents if i.rule == expected] if expected else []
    span = (last_ts - first_ts) if first_ts is not None else 0.0
    return {
        "file": path.name,
        "category": category,
        "expected_rule": expected or "(none: benign)",
        "packets": packets,
        "span_s": round(span, 1),
        "incidents": len(incidents),
        "incidents_by_rule": dict(by_rule),
        "detected": (bool(hit) if expected else None),
        "seconds_to_detect": (round(min(i.first_seen for i in hit) - first_ts, 2) if hit else None),
        "false_alarms": (len(incidents) if not expected else
                         sum(n for r, n in by_rule.items() if r != expected)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", help=".pcap files, or folders containing them")
    parser.add_argument("--max-packets", type=int, default=None)
    parser.add_argument("--rules", default=None)
    parser.add_argument("--out", default="validation/out/pcap_results.csv")
    args = parser.parse_args()

    files: list[Path] = []
    for p in map(Path, args.paths):
        files.extend(sorted(p.glob("*.pcap")) if p.is_dir() else [p])
    config = load_rules(args.rules) if args.rules else load_rules()

    rows = [run_file(f, config, args.max_packets) for f in files]

    print(f"{'file':<36}{'expected rule':<16}{'packets':>9}{'span s':>9}"
          f"{'detected':>10}{'t (s)':>8}{'other alerts':>14}")
    for r in rows:
        det = "-" if r["detected"] is None else ("yes" if r["detected"] else "NO")
        t = "-" if r["seconds_to_detect"] is None else f"{r['seconds_to_detect']}"
        print(f"{r['file']:<36}{r['expected_rule']:<16}{r['packets']:>9}{r['span_s']:>9}"
              f"{det:>10}{t:>8}{r['false_alarms']:>14}")
    print("\nIncidents by rule, per file:")
    for r in rows:
        print(f"  {r['file']:<36}{r['incidents_by_rule'] or '{}'}")

    benign = [r for r in rows if r["detected"] is None]
    for r in benign:
        hours = max(r["span_s"], 1) / 3600
        print(f"\nBenign false alarms: {r['false_alarms']} over {r['span_s']}s "
              f"({r['false_alarms'] / hours:.1f} per hour)")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow({**r, "incidents_by_rule": str(r["incidents_by_rule"])})
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
