"""Repeatable checks: each rule fires on its loud attack, stays quiet on
normal traffic, and the noise controls (ARP grace period, whitelist,
incident grouping) behave as designed.

Run:  python -m unittest discover -s tests
"""

import random
import unittest

import _bootstrap  # noqa: F401
from iotsentinel import attack_simulator as atk
from iotsentinel import device_simulator as dev
from iotsentinel.models import TrafficRecord
from iotsentinel.pipeline import Pipeline, load_rules

T0 = 1_000_000.0


def run(records, config=None):
    pipeline = Pipeline(config or load_rules())
    pipeline.process_stream(sorted(records, key=lambda r: r.timestamp))
    return pipeline


def baseline(seconds=120):
    return list(dev.normal_traffic(seconds, T0, rng=random.Random(1)))


class NormalTraffic(unittest.TestCase):
    def test_normal_traffic_raises_no_incidents(self):
        p = run(baseline())
        self.assertEqual(p.incidents, [])


class LoudAttacks(unittest.TestCase):
    def _assert_rule_fires(self, attack, rule, device, **kwargs):
        records = baseline() + list(atk.ATTACKS[attack](
            start_time=T0 + 30, device_name=device, rng=random.Random(2), **kwargs))
        p = run(records)
        rules = {i.rule for i in p.incidents}
        self.assertIn(rule, rules, f"{attack} did not raise a {rule} incident")

    def test_flooding(self):
        self._assert_rule_fires("flooding", "flooding", "camera-1", duration_s=10)

    def test_port_scan(self):
        self._assert_rule_fires("port_scan", "port_scan", "door-lock-1", duration_s=10)

    def test_brute_force(self):
        self._assert_rule_fires("brute_force", "brute_force", "voice-assistant-1", duration_s=65)

    def test_arp_spoof(self):
        self._assert_rule_fires("arp_spoof", "arp_spoof", "smart-bulb-1")

    def test_botnet(self):
        self._assert_rule_fires("botnet", "botnet", "thermostat-1", duration_s=30)


class SlowAttacksEvadeFixedThresholds(unittest.TestCase):
    """Documents the rules' limits: these are expected to be missed."""

    def test_slow_port_scan_is_missed(self):
        records = baseline() + list(atk.port_scan_slow(
            duration_s=40, start_time=T0 + 30, device_name="camera-1"))
        p = run(records)
        self.assertNotIn("port_scan", {i.rule for i in p.incidents})

    def test_slow_brute_force_is_missed(self):
        records = baseline(200) + list(atk.brute_force_slow(
            duration_s=120, start_time=T0 + 30, device_name="door-lock-1"))
        p = run(records)
        self.assertNotIn("brute_force", {i.rule for i in p.incidents})

    def test_slow_flood_is_missed(self):
        # 40 packets/s is ~400 per 10 s window, under the 500 threshold.
        records = baseline() + list(atk.flooding_slow(
            duration_s=40, start_time=T0 + 30, device_name="smart-plug-1",
            rng=random.Random(5)))
        p = run(records)
        self.assertNotIn("flooding", {i.rule for i in p.incidents})

    def test_slow_botnet_is_missed(self):
        # 4 telnet hosts per 30 s, under the 10-host threshold.
        records = baseline() + list(atk.botnet_slow(
            duration_s=60, start_time=T0 + 30, device_name="thermostat-1"))
        p = run(records)
        self.assertNotIn("botnet", {i.rule for i in p.incidents})


class ArpNoiseControls(unittest.TestCase):
    def test_dhcp_reassignment_does_not_alert(self):
        records = baseline() + list(dev.dhcp_reassignment(
            T0 + 30, device_name="smart-plug-1", rng=random.Random(3)))
        p = run(records)
        self.assertNotIn("arp_spoof", {i.rule for i in p.incidents})

    def test_whitelisted_pair_never_alerts(self):
        config = load_rules()
        config["rules"]["arp_spoof"]["whitelist"] = [
            {"ip": "10.0.0.15", "mac": atk.ATTACKER_MAC}]
        records = baseline() + list(atk.arp_spoof(
            start_time=T0 + 30, device_name="smart-bulb-1"))
        p = run(records, config)
        self.assertNotIn("arp_spoof", {i.rule for i in p.incidents})

    def test_zero_grace_misses_contention(self):
        config = load_rules()
        config["rules"]["arp_spoof"]["grace_period_seconds"] = 0
        records = baseline() + list(atk.arp_spoof(
            start_time=T0 + 30, device_name="smart-bulb-1"))
        p = run(records, config)
        self.assertNotIn("arp_spoof", {i.rule for i in p.incidents})


class IncidentGrouping(unittest.TestCase):
    def test_flood_collapses_to_one_incident_and_escalates(self):
        records = baseline() + list(atk.flooding(
            duration_s=10, start_time=T0 + 30, device_name="camera-1", rng=random.Random(4)))
        p = run(records)
        floods = [i for i in p.incidents if i.rule == "flooding"]
        self.assertEqual(len(floods), 1)
        self.assertGreater(p.violations_seen, 100)
        self.assertEqual(floods[0].severity, "critical")


class FlowCollector(unittest.TestCase):
    def test_malformed_records_are_dropped(self):
        bad = TrafficRecord(timestamp=T0, src_ip="", src_mac="x", dst_ip="10.0.0.11",
                            dst_device="camera-1", dst_port=80, protocol="tcp", event="packet")
        worse = TrafficRecord(timestamp=T0, src_ip="1.2.3.4", src_mac="x", dst_ip="10.0.0.11",
                              dst_device="camera-1", dst_port=70000, protocol="tcp", event="packet")
        p = run([bad, worse])
        self.assertEqual(p.collector.stats(), {"accepted": 0, "dropped": 2})


if __name__ == "__main__":
    unittest.main()
