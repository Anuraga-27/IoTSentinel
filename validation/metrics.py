"""Matches detected incidents against ground-truth attack windows and
computes precision, recall and false-positive rate per attack type."""

from __future__ import annotations

from dataclasses import dataclass

import _bootstrap  # noqa: F401
from iotsentinel.rule_engine import Incident
from scenarios import GroundTruthWindow

DETECTION_LATENCY_TOLERANCE_S = 5.0


@dataclass
class ScoreRow:
    label: str
    rule: str | None
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    detectable_windows: int = 0

    @property
    def recall(self) -> float | None:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else None

    @property
    def precision(self) -> float | None:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else None


def _overlaps(incident: Incident, window: GroundTruthWindow) -> bool:
    if incident.target != window.target:
        return False
    latest_start = max(incident.first_seen, window.start)
    earliest_end = min(incident.last_seen, window.end + DETECTION_LATENCY_TOLERANCE_S)
    return latest_start <= earliest_end


def score(windows: list[GroundTruthWindow], incidents: list[Incident]) -> dict:
    rows: dict[str, ScoreRow] = {}
    matched_incident_ids: set[str] = set()

    attack_windows = [w for w in windows if w.expected_rule is not None]
    benign_windows = [w for w in windows if w.expected_rule is None]

    for w in attack_windows:
        row = rows.setdefault(w.label, ScoreRow(w.label, w.expected_rule))
        hit = next((i for i in incidents
                    if i.rule == w.expected_rule and _overlaps(i, w)), None)
        if hit is not None:
            row.true_positives += 1
            matched_incident_ids.add(hit.id)
        else:
            row.false_negatives += 1
        if w.detectable:
            row.detectable_windows += 1

    # Any incident that doesn't correspond to a real attack window is a
    # false positive -- this is what the hard benign cases are designed to surface.
    fp_row = rows.setdefault("normal", ScoreRow("normal", None))
    for i in incidents:
        if i.id in matched_incident_ids:
            continue
        overlaps_benign = any(_overlaps(i, w) for w in benign_windows)
        overlaps_attack_wrong_rule = any(
            i.target == w.target and w.start <= i.first_seen <= w.end + DETECTION_LATENCY_TOLERANCE_S
            for w in attack_windows
        )
        if overlaps_benign or not overlaps_attack_wrong_rule:
            fp_row.false_positives += 1
            row = rows.setdefault(i.rule, ScoreRow(i.rule, i.rule))
            if row is not fp_row:
                row.false_positives += 1

    n_benign_opportunities = len(benign_windows) if benign_windows else 1
    fpr = fp_row.false_positives / n_benign_opportunities

    return {"rows": rows, "false_positive_rate_per_benign_case": fpr,
            "total_incidents": len(incidents)}


def print_report(result: dict) -> None:
    rows = result["rows"]
    print(f"{'attack':<14}{'TP':>4}{'FN':>4}{'FP':>4}{'recall':>9}{'precision':>11}")
    for label, row in rows.items():
        if label == "normal":
            continue
        recall = f"{row.recall:.2f}" if row.recall is not None else "n/a"
        precision = f"{row.precision:.2f}" if row.precision is not None else "n/a"
        print(f"{label:<14}{row.true_positives:>4}{row.false_negatives:>4}"
              f"{row.false_positives:>4}{recall:>9}{precision:>11}")
    print()
    print(f"False positives on benign/hard-benign cases: "
          f"{rows['normal'].false_positives} "
          f"(rate per benign case: {result['false_positive_rate_per_benign_case']:.2f})")
    print(f"Total incidents raised: {result['total_incidents']}")
