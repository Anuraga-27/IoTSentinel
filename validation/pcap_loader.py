"""Reads real packets from a classic .pcap file (Ethernet link type) and
turns them into IoTSentinel TrafficRecords, so the rules can be tested on
traffic we did not generate ourselves.

Uses only the standard library. A file cut off mid-packet (as our
downloaded samples are) is read up to the last complete packet.

What each packet becomes:
- ARP (request or reply): an "arp_announce" binding the sender IP to the
  sender MAC. This is the real signal the ARP rule needs.
- IPv4 TCP/UDP/ICMP: a "packet" from src to dst, with the real
  destination port. The destination IP stands in for the device name.
- TCP SYN (no ACK) to a telnet port: also a telnet "connect".
- TCP SYN (no ACK) to a login port: also a "login_failed".

That last mapping is a proxy. Whether a login failed lives inside the
application data, which a packet capture of encrypted or binary protocols
does not show. Counting connection attempts to login services is the
closest observable stand-in; say so when reporting brute-force results.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

import _bootstrap  # noqa: F401
from iotsentinel.models import TrafficRecord

TELNET_PORTS = {23, 2323}
LOGIN_PORTS = {21, 22, 23, 2323}

_ETH_IPV4 = 0x0800
_ETH_ARP = 0x0806
_ETH_VLAN = 0x8100


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _packets(path: Path) -> Iterator[tuple[float, bytes]]:
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError(f"{path.name} is not a classic pcap file (pcapng is not supported)")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != 1:
            raise ValueError(f"{path.name} has link type {linktype}; only Ethernet (1) is supported")
        divisor = 1e9 if nano else 1e6
        rec = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, caplen, _ = rec.unpack(h)
            data = f.read(caplen)
            if len(data) < caplen:
                return  # truncated final packet
            yield sec + frac / divisor, data


def read_pcap(path: str | Path, label: str = "unknown",
              max_packets: int | None = None) -> Iterator[TrafficRecord]:
    path = Path(path)
    for n, (ts, frame) in enumerate(_packets(path)):
        if max_packets is not None and n >= max_packets:
            return
        if len(frame) < 14:
            continue
        dst_mac, src_mac = frame[0:6], frame[6:12]
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        if ethertype == _ETH_VLAN and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18

        if ethertype == _ETH_ARP and len(frame) >= offset + 28:
            arp = frame[offset:offset + 28]
            sender_mac, sender_ip = arp[8:14], _ip(arp[14:18])
            if sender_ip == "0.0.0.0":
                continue  # ARP probe, claims no address
            yield TrafficRecord(
                timestamp=ts, src_ip=sender_ip, src_mac=_mac(sender_mac),
                dst_ip=sender_ip, dst_device=sender_ip, dst_port=0,
                protocol="arp", event="arp_announce", size_bytes=len(frame), label=label,
            )
            continue

        if ethertype != _ETH_IPV4 or len(frame) < offset + 20:
            continue
        ip = frame[offset:]
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src_ip, dst_ip = _ip(ip[12:16]), _ip(ip[16:20])
        l4 = ip[ihl:]
        src_port, dst_port, flags = 0, 0, 0
        if proto in (6, 17) and len(l4) >= 4:
            src_port, dst_port = struct.unpack("!HH", l4[0:4])
        if proto == 6 and len(l4) >= 14:
            flags = l4[13]
        name = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, f"ip{proto}")

        is_syn = bool(proto == 6 and (flags & 0x02) and not (flags & 0x10))
        if proto == 6:
            initiates = is_syn
        elif proto == 17:
            # UDP has no handshake. Heuristic: a packet aimed at the lower of
            # the two ports is going to a service, so it opens the exchange.
            initiates = dst_port < src_port
        else:
            initiates = False  # ICMP and others carry no port to scan

        common = dict(timestamp=ts, src_ip=src_ip, src_mac=_mac(src_mac),
                      dst_ip=dst_ip, dst_device=dst_ip, dst_port=dst_port,
                      size_bytes=len(frame), label=label, initiates=initiates)
        yield TrafficRecord(protocol=name, event="packet", **common)

        if is_syn and dst_port in TELNET_PORTS:
            yield TrafficRecord(protocol="telnet", event="connect", **common)
        if is_syn and dst_port in LOGIN_PORTS:
            yield TrafficRecord(protocol="tcp", event="login_failed", **common)
