#!/usr/bin/env python3
"""Regenerate the golden fixture for the `tc8-harness decode-pcap` test.

Writes a small, deterministic pcap (ARP / ICMPv4 / UDP / DHCPv4 / TCP /
SOME/IP RPC / SOME/IP-SD / Upper-Tester / SOME/IP-over-TCP / IPv6) plus a
matching transition-trace sidecar. The decode_pcap_golden ctest replays the
pcap through the real binary and diffs the result against the committed
expected JSON, so the exporter's output is gated on every build (this is the
automated guard that replaced the deleted .def `--check` gates; see
docs/tech-debt.md TD-05).

To refresh after an intentional exporter change:
    python3 unit_tests/fixtures/gen_decode_pcap_fixture.py
    ./build/tc8-harness decode-pcap GOLDEN pass \
        unit_tests/fixtures/decode_pcap_sample.pcap \
        --captured-at 2020-01-01T00:00:00Z \
        --trace-json unit_tests/fixtures/decode_pcap_sample.trace.json \
        --out unit_tests/fixtures/decode_pcap_sample.expected.json
"""
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTER_MAC = bytes.fromhex("020000000001")
DUT_MAC = bytes.fromhex("020000000002")
BCAST = b"\xff" * 6
TESTER_IP = bytes([192, 168, 0, 10])
DUT_IP = bytes([192, 168, 0, 1])

frames = []
_t = [1_000_000]


def add(frame, dt=1000):
    frames.append((_t[0], frame))
    _t[0] += dt


def eth(dst, src, et, payload):
    return dst + src + struct.pack(">H", et) + payload


def ipv4(src, dst, proto, payload):
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0) + src + dst
    s = sum(struct.unpack(">H", hdr[i:i + 2])[0] for i in range(0, len(hdr), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    hdr = hdr[:10] + struct.pack(">H", (~s) & 0xFFFF) + hdr[12:]
    return hdr + payload


def udp(sp, dp, payload):
    return struct.pack(">HHHH", sp, dp, 8 + len(payload), 0) + payload


def tcp(sp, dp, seq, ack, flags, win=64240, payload=b""):
    off_flags = (5 << 12) | flags
    return struct.pack(">HHIIHHHH", sp, dp, seq, ack, off_flags, win, 0, 0) + payload


def someip(svc, mth, cli, sess, mt, rc, payload=b""):
    return struct.pack(">HHIHHBBBB", svc, mth, 8 + len(payload), cli, sess, 1, 1, mt, rc) + payload


def arp(op, smac, sip, tmac, tip):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + smac + sip + tmac + tip


def icmp(typ, code, ident, seq, data=b"abcdefgh"):
    body = struct.pack(">BBHHH", typ, code, 0, ident, seq) + data
    s = 0
    for i in range(0, len(body) - (len(body) % 2), 2):
        s += struct.unpack(">H", body[i:i + 2])[0]
    if len(body) % 2:
        s += body[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return struct.pack(">BBHHH", typ, code, (~s) & 0xFFFF, ident, seq) + data


def dhcp_discover(xid):
    b = struct.pack(">BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000) + b"\x00" * 16
    b += DUT_MAC + b"\x00" * 10 + b"\x00" * 192
    b += bytes([0x63, 0x82, 0x53, 0x63, 53, 1, 1, 255])
    return b


def sd_offer():
    entry = struct.pack(">BBBB", 0x01, 0, 0, 0x10) + struct.pack(">HH", 0x1234, 0x0001)
    entry += struct.pack(">I", (0x01 << 24) | 3) + struct.pack(">I", 0)
    opt = struct.pack(">HBB", 0x0009, 0x04, 0x00) + DUT_IP + struct.pack(">BBH", 0x00, 0x11, 30509)
    payload = b"\x00\x00\x00\x00" + struct.pack(">I", len(entry)) + entry
    payload += struct.pack(">I", len(opt)) + opt
    return someip(0xFFFF, 0x8100, 0x0000, 0x0001, 0x02, 0x00, payload)


# idx 0..1 ARP
add(eth(BCAST, TESTER_MAC, 0x0806, arp(1, TESTER_MAC, TESTER_IP, b"\x00" * 6, DUT_IP)))
add(eth(TESTER_MAC, DUT_MAC, 0x0806, arp(2, DUT_MAC, DUT_IP, TESTER_MAC, TESTER_IP)))
# idx 2..3 ICMP echo
add(eth(DUT_MAC, TESTER_MAC, 0x0800, ipv4(TESTER_IP, DUT_IP, 1, icmp(8, 0, 0x1234, 1))))
add(eth(TESTER_MAC, DUT_MAC, 0x0800, ipv4(DUT_IP, TESTER_IP, 1, icmp(0, 0, 0x1234, 1))))
# idx 4 DHCP discover
add(eth(BCAST, DUT_MAC, 0x0800, ipv4(bytes([0, 0, 0, 0]), bytes([255, 255, 255, 255]), 17, udp(68, 67, dhcp_discover(0xdeadbeef)))))
# idx 5..6 TCP SYN + data
add(eth(DUT_MAC, TESTER_MAC, 0x0800, ipv4(TESTER_IP, DUT_IP, 6, tcp(50000, 80, 1000, 0, 0x02))))
add(eth(DUT_MAC, TESTER_MAC, 0x0800, ipv4(TESTER_IP, DUT_IP, 6, tcp(50000, 80, 1001, 5001, 0x18, payload=b"DATA"))))
# idx 7..8 SOME/IP RPC over UDP 30490
add(eth(DUT_MAC, TESTER_MAC, 0x0800, ipv4(TESTER_IP, DUT_IP, 17, udp(40002, 30490, someip(0x1234, 0x0001, 0x0001, 0x0001, 0x00, 0x00, b"\x01\x02")))))
add(eth(TESTER_MAC, DUT_MAC, 0x0800, ipv4(DUT_IP, TESTER_IP, 17, udp(30490, 40002, someip(0x1234, 0x0001, 0x0001, 0x0001, 0x80, 0x00, b"\x03\x04")))))
# idx 9 SOME/IP-SD OfferService
add(eth(TESTER_MAC, DUT_MAC, 0x0800, ipv4(DUT_IP, TESTER_IP, 17, udp(30490, 30490, sd_offer()))))
# idx 10..11 UT GetReceivedUdp req + resp
add(eth(DUT_MAC, TESTER_MAC, 0x0800, ipv4(TESTER_IP, DUT_IP, 17, udp(45000, 30600, bytes([0x01, 0x07])))))
add(eth(TESTER_MAC, DUT_MAC, 0x0800, ipv4(DUT_IP, TESTER_IP, 17, udp(30600, 45000, bytes([0x81, 0x07, 0x00, 0x01]) + bytes([192, 168, 0, 99]) + struct.pack(">HH", 12345, 5)))))
# idx 12 IPv6 (unknown ethertype)
add(eth(TESTER_MAC, DUT_MAC, 0x86DD, b"\x60" + b"\x00" * 39))
# idx 13 sub-240 DHCP: BOOTP body too short for the magic cookie (offset 236),
# so the pipeline raises no Dhcpv4Frame and the exporter labels the UDP datagram
# on the 67/68 port pair "DHCPv4 (truncated, N B)" (docs/tech-debt.md TD-09).
add(eth(BCAST, DUT_MAC, 0x0800, ipv4(bytes([0, 0, 0, 0]), bytes([255, 255, 255, 255]), 17, udp(68, 67, b"\x01\x01\x06\x00" + b"\x00" * 96))))

with (HERE / "decode_pcap_sample.pcap").open("wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in frames:
        fh.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(frame), len(frame)))
        fh.write(frame)

# Matching transition trace: two fired transitions (idx 7 request, idx 8 pass)
# plus a synthetic (non-retained) step, exercising the verbatim merge.
trace = {
    "steps": [
        {"step": 0, "event": "someip_observed", "from_state": "await",
         "to_state": "called", "pcap_frame_idx": 7},
        {"step": 1, "event": "someip_observed", "from_state": "called",
         "to_state": "pass", "pcap_frame_idx": 8},
        {"step": 2, "event": "deadline_exceeded", "from_state": "pass",
         "to_state": "pass", "pcap_frame_idx": None,
         "captured_delta": {"note": "timer"}},
    ],
    "final_state": "pass",
}
(HERE / "decode_pcap_sample.trace.json").write_text(
    json.dumps(trace, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(frames)}-frame fixture + trace to {HERE}")
