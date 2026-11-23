"""Sweeps each rule's threshold (or the ARP grace period) across a range and
plots detection rate against false-alarm rate, using the same labeled
corpus every time -- including the hard benign cases and slow/stealthy
attacks that stay under the default thresholds, so the rules' real limits
are visible rather than hidden by self-generated traffic that is always
either obviously benign or obviously loud.

Usage:
    python validation/threshold_sweep.py
    python validation/threshold_sweep.py --out-dir out
"""

from __future__ import annotations

import argparse
import copy
import csv
from pathlib import Path

import _bootstrap  # noqa: F401
from iotsentinel.pipeline import Pipeline, load_rules

import metrics
from scenarios import build_corpus

SWEEPS = {
    "flooding": {
        "path": ("rules", "flooding", "threshold"),
        "values": [100, 250, 500, 750, 1000, 1500, 2000, 3000, 4000, 5000],
    },
    "port_scan": {
        "path": ("rules", "port_scan", "threshold"),
        "values": [2, 4, 6, 8, 10, 15, 20, 30, 40],
    },
    "brute_force": {
        "path": ("rules", "brute_force", "threshold"),
        "values": [1, 2, 3, 4, 5, 8, 12, 16, 20],
    },
    "botnet": {
        "path": ("rules", "botnet", "threshold"),
        "values": [1, 2, 4, 6, 8, 10, 15, 20, 25],
    },
    "arp_spoof_grace": {
        "path": ("rules", "arp_spoof", "grace_period_seconds"),
        # fine-grained near 1s: the loud attack's confirming contention
        # packet arrives 1s after the spoofed announcement, so recall
        # should flip from 0 to 1 right around there.
        "values": [0, 0.25, 0.5, 0.75, 1.0, 1.5, 2, 5, 10, 30, 60],
    },
}


def set_path(config: dict, path: tuple, value) -> dict:
    cfg = copy.deepcopy(config)
    node = cfg
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return cfg


def rule_for_sweep(sweep_name: str) -> str:
    return "arp_spoof" if sweep_name.startswith("arp_spoof") else sweep_name


def run_sweep(sweep_name: str, base_config: dict, records, windows) -> list[dict]:
    spec = SWEEPS[sweep_name]
    rule = rule_for_sweep(sweep_name)
    rows = []
    for value in spec["values"]:
        config = set_path(base_config, spec["path"], value)
        pipeline = Pipeline(config)
        incidents = pipeline.process_stream(records)
        result = metrics.score(windows, incidents)
        row = result["rows"].get(rule)
        # detection rate across ALL windows for this rule (loud + slow),
        # so the curve shows where stealthy attacks stop being caught.
        attack_windows = [w for w in windows if w.expected_rule == rule]
        tp = sum(1 for w in attack_windows
                 if any(i.rule == rule and i.target == w.target
                        and w.start <= i.first_seen <= w.end + metrics.DETECTION_LATENCY_TOLERANCE_S
                        for i in incidents))
        detection_rate = tp / len(attack_windows) if attack_windows else None
        false_alarms = row.false_positives if row else 0
        rows.append({
            "sweep": sweep_name, "value": value,
            "detection_rate": detection_rate,
            "false_alarms": false_alarms,
            "true_positives": tp,
            "attack_windows": len(attack_windows),
        })
    return rows


def write_csv(all_rows: list[dict], out_path: Path) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)


def try_plot(all_rows: list[dict], out_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping PNG plots "
              "(pip install matplotlib). CSV results were still written.")
        return

    by_sweep: dict[str, list[dict]] = {}
    for row in all_rows:
        by_sweep.setdefault(row["sweep"], []).append(row)

    for sweep_name, rows in by_sweep.items():
        rows = sorted(rows, key=lambda r: r["value"])
        fig, ax1 = plt.subplots(figsize=(6, 4))
        ax1.plot([r["value"] for r in rows],
                 [r["detection_rate"] or 0 for r in rows],
                 marker="o", color="#2a8", label="Detection rate")
        ax1.set_xlabel("threshold" if "grace" not in sweep_name else "grace period (s)")
        ax1.set_ylabel("detection rate", color="#2a8")
        ax1.set_ylim(-0.05, 1.05)

        ax2 = ax1.twinx()
        ax2.plot([r["value"] for r in rows],
                 [r["false_alarms"] for r in rows],
                 marker="s", color="#d33", label="False alarms")
        ax2.set_ylabel("false alarms (count)", color="#d33")

        plt.title(f"Threshold sweep: {sweep_name}")
        fig.tight_layout()
        out_path = out_dir / f"sweep_{sweep_name}.png"
        fig.savefig(out_path, dpi=150)
        plt.close(fig)
        print(f"Wrote {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="validation/out")
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    base_config = load_rules()
    records, windows = build_corpus()

    all_rows: list[dict] = []
    for sweep_name in SWEEPS:
        rows = run_sweep(sweep_name, base_config, records, windows)
        all_rows.extend(rows)
        print(f"\n{sweep_name}:")
        for r in rows:
            dr = f"{r['detection_rate']:.2f}" if r["detection_rate"] is not None else "n/a"
            print(f"  value={r['value']:<8} detection_rate={dr:<6} false_alarms={r['false_alarms']}")

    csv_path = out_dir / "threshold_sweep_results.csv"
    write_csv(all_rows, csv_path)
    print(f"\nWrote {csv_path}")
    try_plot(all_rows, out_dir)


if __name__ == "__main__":
    main()
