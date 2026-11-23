"""Wires flow collector -> rule engine -> incident grouper -> alert store
into the single pipeline used by both the live dashboard and the
validation/testing scripts."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

import yaml

from .alert_store import AlertStore
from .flow_collector import FlowCollector
from .models import TrafficRecord
from .rule_engine import Incident, IncidentGrouper, RuleEngine, Violation

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "rules.yaml"


def load_rules(path: str | Path = DEFAULT_RULES_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


class Pipeline:
    def __init__(self, rules_config: Optional[dict] = None,
                 store: Optional[AlertStore] = None):
        self.config = rules_config or load_rules()
        self.collector = FlowCollector()
        self.engine = RuleEngine(self.config)
        grouping_cfg = self.config.get("incident_grouping", {})
        self.grouper = IncidentGrouper(
            grouping_cfg.get("group_window_seconds", 60),
            grouping_cfg.get("escalation_repeat_counts", {}),
        )
        self.store = store
        self.device_last_incident: dict[str, Incident] = {}
        self.violations_seen = 0
        self.incidents: list[Incident] = []

    def _ingest(self, rec: TrafficRecord, touched: dict) -> list[Incident]:
        new_incidents = []
        for good in self.collector.process([rec]):
            for v in self.engine.ingest(good):
                self.violations_seen += 1
                incident, is_new = self.grouper.add(v)
                if is_new:
                    self.incidents.append(incident)
                    new_incidents.append(incident)
                self.device_last_incident[incident.target] = incident
                touched[incident.id] = incident
        return new_incidents

    def process_record(self, rec: TrafficRecord) -> list[Incident]:
        return self.process_stream([rec])

    def process_stream(self, records: Iterable[TrafficRecord]) -> list[Incident]:
        # write each touched incident once per batch, not once per violation
        touched: dict[str, Incident] = {}
        out = []
        for rec in records:
            out.extend(self._ingest(rec, touched))
        if self.store is not None and touched:
            self.store.upsert_incidents(touched.values())
        return out

    def device_status(self, device_name: str, now: float, clear_after_s: float = 15.0) -> str:
        """'alert' if the device has an incident within clear_after_s of now,
        else 'ok'."""
        inc = self.device_last_incident.get(device_name)
        if inc is None:
            return "ok"
        if now - inc.last_seen <= clear_after_s:
            return "alert"
        return "ok"
