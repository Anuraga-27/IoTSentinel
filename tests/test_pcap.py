"""Tests the PCAP reader on tiny captures built in memory, and the port-scan
rule's option to count only connection attempts."""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

import _bootstrap  # noqa: F401
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "validation"))
import pcap_loader  # noqa: E402
from iotsentinel.models import TrafficRecord  # noqa: E402
from iotsentinel.pipeline import Pipeline, load_rules  # noqa: E402

MAC_A = bytes.fromhex("aabbcc000001")
MAC_B = bytes.fromhex("aabbcc000002")


def ip(s):
    return bytes(int(x) for x in s.split("."))


def eth(dst, src, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


def arp(sender_mac, sender_ip):
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + sender_mac + ip(sender_ip) + MAC_B + ip("10.0.0.1")


def tcp(src, dst, sport, dport, flags):
    t = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1024, 0, 0)
    h = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(t), 0, 0, 64, 6, 0) + ip(src) + ip(dst)
    return h + t


def write_pcap(frames, truncate_last=False):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for n, f in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + n, 0, len(f), len(f)) + f
    if truncate_last:
        out = out[:-5]
    path = Path(tempfile.mkdtemp()) / "test.pcap"
    path.write_bytes(out)
    return path


class PcapReader(unittest.TestCase):
    def test_arp_becomes_binding(self):
        recs = list(pcap_loader.read_pcap(write_pcap([eth(MAC_B, MAC_A, 0x0806, arp(MAC_A, "10.0.0.5"))])))
        self.assertEqual(len(recs), 1)
        self.assertEqual((recs[0].event, recs[0].dst_ip, recs[0].src_mac),
                         ("arp_announce", "10.0.0.5", "AA:BB:CC:00:00:01"))

    def test_syn_initiates_and_reply_does_not(self):
        syn = eth(MAC_B, MAC_A, 0x0800, tcp("10.0.0.5", "10.0.0.9", 50000, 22, 0x02))
        synack = eth(MAC_A, MAC_B, 0x0800, tcp("10.0.0.9", "10.0.0.5", 22, 50000, 0x12))
        recs = list(pcap_loader.read_pcap(write_pcap([syn, synack])))
        packets = [r for r in recs if r.event == "packet"]
        self.assertEqual([p.initiates for p in packets], [True, False])
        self.assertEqual(sum(r.event == "login_failed" for r in recs), 1)

    def test_truncated_final_packet_is_skipped(self):
        frames = [eth(MAC_B, MAC_A, 0x0800, tcp("10.0.0.5", "10.0.0.9", 50000, 80, 0x02))] * 3
        recs = [r for r in pcap_loader.read_pcap(write_pcap(frames, truncate_last=True))
                if r.event == "packet"]
        self.assertEqual(len(recs), 2)


class PortScanCountsAttemptsOnly(unittest.TestCase):
    def _server_replies(self):
        # a server answering one client on 40 different ephemeral ports
        return [TrafficRecord(timestamp=1_000_000 + i * 0.1, src_ip="10.0.0.9", src_mac="x",
                              dst_ip="10.0.0.5", dst_device="10.0.0.5", dst_port=40000 + i,
                              protocol="tcp", event="packet", initiates=False)
                for i in range(40)]

    def test_replies_are_ignored_when_enabled(self):
        p = Pipeline(load_rules())
        p.process_stream(self._server_replies())
        self.assertNotIn("port_scan", {i.rule for i in p.incidents})

    def test_replies_count_when_disabled(self):
        config = load_rules()
        config["rules"]["port_scan"]["count_only_connection_attempts"] = False
        p = Pipeline(config)
        p.process_stream(self._server_replies())
        self.assertIn("port_scan", {i.rule for i in p.incidents})


if __name__ == "__main__":
    unittest.main()
