#!/usr/bin/env python3
"""Decode a per-case pcap file into the site's PacketCapture JSON shape.

Run by CI after each test execution:

    site/scripts/decode_pcap.py <CASE_ID> <pass|fail> <pcap_file> \
        --tester-mac 02:00:00:00:00:01 --tester-ip 192.168.0.10 \
        --dut-mac 02:00:00:00:00:02    --dut-ip 192.168.0.1 \
        --out site/src/data/pcap/<CASE_ID>.json

Output format is documented in ``site/src/lib/types.ts`` (PacketCapture).
A pure-Python pcap reader handles ARP / ICMPv4 / IPv4+UDP / IPv4+TCP — the
TC8 protocol surface — without external dependencies. Other link-layer or
upper-layer protocols are reported as ``UNKNOWN`` with raw byte length so
the timeline still surfaces them.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_NS_LE = 0xA1B23C4D


@dataclass
class Packet:
    idx: int
    ts_us: int
    ts_delta_us: int
    direction: str
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = "UNKNOWN"
    summary: str = ""
    fields: dict = field(default_factory=dict)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def _read_pcap(path: Path):
    """Yield ``(ts_us, ethernet_frame_bytes)`` for every packet in a pcap."""
    with path.open("rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack("<I", header[:4])[0]
        ts_scale_us = 1 if magic == PCAP_MAGIC_LE else (
            1 / 1000 if magic == PCAP_MAGIC_NS_LE else None)
        if ts_scale_us is None:
            raise SystemExit(f"unsupported pcap magic 0x{magic:08x}")
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack("<IIII", rec)
            data = fh.read(incl_len)
            if len(data) < incl_len:
                return
            ts_us = ts_sec * 1_000_000 + int(ts_sub * ts_scale_us)
            yield ts_us, data


def _dissect_ethernet(frame: bytes, p: Packet) -> bytes | None:
    if len(frame) < 14:
        return None
    p.dst_mac = _mac(frame[:6])
    p.src_mac = _mac(frame[6:12])
    eth_type = struct.unpack(">H", frame[12:14])[0]
    rest = frame[14:]
    if eth_type == 0x0806:
        _dissect_arp(rest, p)
        return None
    if eth_type == 0x0800:
        return _dissect_ipv4(rest, p)
    p.protocol = f"ETH 0x{eth_type:04x}"
    p.summary = f"{len(frame)} B"
    return None


def _dissect_arp(payload: bytes, p: Packet) -> None:
    p.protocol = "ARP"
    if len(payload) < 28:
        p.summary = "truncated ARP"
        return
    opcode = struct.unpack(">H", payload[6:8])[0]
    sender_mac = _mac(payload[8:14])
    sender_ip = _ip(payload[14:18])
    target_mac = _mac(payload[18:24])
    target_ip = _ip(payload[24:28])
    p.fields = {
        "opcode": opcode, "sender_mac": sender_mac, "sender_ip": sender_ip,
        "target_mac": target_mac, "target_ip": target_ip,
    }
    if opcode == 1:
        p.summary = f"Who has {target_ip}? Tell {sender_ip} (sender_mac={sender_mac})"
    elif opcode == 2:
        p.summary = f"{sender_ip} is at {sender_mac}"
    else:
        p.summary = f"opcode={opcode}"


def _dissect_ipv4(payload: bytes, p: Packet) -> bytes | None:
    if len(payload) < 20:
        p.protocol = "IPv4"
        p.summary = "truncated"
        return None
    ihl = (payload[0] & 0x0F) * 4
    proto = payload[9]
    p.src_ip = _ip(payload[12:16])
    p.dst_ip = _ip(payload[16:20])
    upper = payload[ihl:]
    if proto == 1:
        _dissect_icmpv4(upper, p)
    elif proto == 6:
        _dissect_tcp(upper, p)
    elif proto == 17:
        _dissect_udp(upper, p)
    else:
        p.protocol = f"IPv4 proto={proto}"
        p.summary = f"{len(payload)} B"
    return None


def _dissect_icmpv4(payload: bytes, p: Packet) -> None:
    p.protocol = "ICMPv4"
    if len(payload) < 4:
        p.summary = "truncated"
        return
    type_, code = payload[0], payload[1]
    p.fields = {"type": type_, "code": code}
    p.summary = f"type={type_} code={code}"


def _dissect_udp(payload: bytes, p: Packet) -> None:
    p.protocol = "UDP"
    if len(payload) < 8:
        p.summary = "truncated"
        return
    sport, dport, length = struct.unpack(">HHH", payload[:6])
    p.fields = {"src_port": sport, "dst_port": dport, "length": length}
    if dport == 67 or sport == 68:
        p.protocol = "DHCPv4"
    elif dport == 30490 or sport == 30490:
        p.protocol = "SOME/IP"
    p.summary = f"{sport} → {dport}, len={length}"


def _dissect_tcp(payload: bytes, p: Packet) -> None:
    p.protocol = "TCP"
    if len(payload) < 20:
        p.summary = "truncated"
        return
    sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", payload[:14])
    flags = off_flags & 0x01FF
    flag_names = []
    if flags & 0x002: flag_names.append("SYN")
    if flags & 0x010: flag_names.append("ACK")
    if flags & 0x001: flag_names.append("FIN")
    if flags & 0x004: flag_names.append("RST")
    if flags & 0x008: flag_names.append("PSH")
    p.fields = {
        "src_port": sport, "dst_port": dport,
        "seq": seq, "ack": ack, "flags": "|".join(flag_names) or "—",
    }
    p.summary = f"{sport} → {dport} [{'|'.join(flag_names) or '—'}] seq={seq} ack={ack}"


def _direction(src_mac: Optional[str], dst_mac: Optional[str],
               tester_mac: Optional[str], dut_mac: Optional[str]) -> str:
    s, d = (src_mac or "").lower(), (dst_mac or "").lower()
    t, dm = (tester_mac or "").lower(), (dut_mac or "").lower()
    if t and s == t: return "tester_to_dut"
    if dm and s == dm: return "dut_to_tester"
    if t and d == t: return "dut_to_tester"
    if dm and d == dm: return "tester_to_dut"
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("case_id")
    ap.add_argument("outcome", choices=["pass", "fail"])
    ap.add_argument("pcap_file", type=Path)
    ap.add_argument("--tester-mac")
    ap.add_argument("--tester-ip")
    ap.add_argument("--dut-mac")
    ap.add_argument("--dut-ip")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--captured-at", default="")
    args = ap.parse_args()

    packets: list[Packet] = []
    first_ts: Optional[int] = None
    prev_ts: Optional[int] = None
    for idx, (ts_us, frame) in enumerate(_read_pcap(args.pcap_file)):
        if first_ts is None:
            first_ts = ts_us
            prev_ts = ts_us
        p = Packet(idx=idx, ts_us=ts_us - first_ts,
                   ts_delta_us=(ts_us - prev_ts) if idx > 0 else 0,
                   direction="other")
        _dissect_ethernet(frame, p)
        p.direction = _direction(p.src_mac, p.dst_mac, args.tester_mac, args.dut_mac)
        packets.append(p)
        prev_ts = ts_us

    out = {
        "case_id": args.case_id.upper(),
        "outcome": args.outcome,
        "captured_at": args.captured_at,
        "tester_mac": args.tester_mac, "tester_ip": args.tester_ip,
        "dut_mac": args.dut_mac, "dut_ip": args.dut_ip,
        "packets": [asdict(p) for p in packets],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"wrote {len(packets)} packet(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
