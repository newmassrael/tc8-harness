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


# RFC 792 + IANA assignments. Only the types TC8 actually exercises are
# named — anything else falls back to the numeric ``type=N code=N`` form.
_ICMPV4_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply", 15: "Information Request",
    16: "Information Reply", 17: "Address Mask Request",
    18: "Address Mask Reply",
}
# RFC 792 §"Destination Unreachable" codes (truncated to TC8 surface).
_ICMPV4_DU_CODES = {
    0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable",
    3: "port unreachable", 4: "fragmentation needed", 5: "source route failed",
}


def _dissect_icmpv4(payload: bytes, p: Packet) -> None:
    p.protocol = "ICMPv4"
    if len(payload) < 4:
        p.summary = "truncated"
        return
    type_, code = payload[0], payload[1]
    p.fields = {"type": type_, "code": code}
    name = _ICMPV4_TYPES.get(type_)
    if type_ == 3:  # Destination Unreachable — code matters
        code_name = _ICMPV4_DU_CODES.get(code, f"code={code}")
        p.summary = f"{name}: {code_name}" if name else f"type={type_} code={code}"
    elif name:
        p.summary = f"{name}" if code == 0 else f"{name} (code={code})"
    else:
        p.summary = f"type={type_} code={code}"


# RFC 2132 §9.6 DHCP Message Type values.
_DHCPV4_MSG_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
    5: "Ack", 6: "Nak", 7: "Release", 8: "Inform",
}


def _dissect_dhcpv4(payload: bytes, p: Packet, src_port: int, dst_port: int) -> None:
    """Parse BOOTP + DHCP option 53 (Message Type) from a UDP 67/68 payload."""
    p.protocol = "DHCPv4"
    # BOOTP fixed part is 236 B + magic cookie (4 B) before options.
    if len(payload) < 240:
        p.summary = f"DHCPv4 (truncated, {len(payload)} B)"
        return
    op = payload[0]
    xid = struct.unpack(">I", payload[4:8])[0]
    chaddr = _mac(payload[28:34])
    cookie = payload[236:240]
    msg_type = None
    if cookie == b"\x63\x82\x53\x63":
        i = 240
        while i < len(payload):
            opt = payload[i]
            if opt == 255:  # End
                break
            if opt == 0:    # Pad
                i += 1
                continue
            if i + 1 >= len(payload):
                break
            ln = payload[i + 1]
            val = payload[i + 2:i + 2 + ln]
            if opt == 53 and ln >= 1:
                msg_type = val[0]
                break
            i += 2 + ln
    name = _DHCPV4_MSG_TYPES.get(msg_type) if msg_type is not None else None
    p.fields = {
        "src_port": src_port, "dst_port": dst_port,
        "op": op, "xid": xid, "chaddr": chaddr,
        "dhcp_msg_type": msg_type,
    }
    if name:
        p.summary = f"DHCPv4 {name} xid=0x{xid:08x} chaddr={chaddr}"
    else:
        op_name = "BOOTREQUEST" if op == 1 else "BOOTREPLY" if op == 2 else f"op={op}"
        p.summary = f"DHCPv4 {op_name} xid=0x{xid:08x}"


# SOME/IP message types per PRS_SOMEIP_00055.
_SOMEIP_MSG_TYPES = {
    0x00: "Request", 0x01: "RequestNoReturn", 0x02: "Notification",
    0x40: "RequestAck", 0x41: "RequestNoReturnAck", 0x42: "NotificationAck",
    0x80: "Response", 0x81: "Error",
    0xC0: "ResponseAck", 0xC1: "ErrorAck",
}
# SOME/IP return codes per PRS_SOMEIP_00191 (TC8-relevant subset).
_SOMEIP_RETURN_CODES = {
    0x00: "E_OK", 0x01: "E_NOT_OK", 0x02: "E_UNKNOWN_SERVICE",
    0x03: "E_UNKNOWN_METHOD", 0x04: "E_NOT_READY", 0x05: "E_NOT_REACHABLE",
    0x06: "E_TIMEOUT", 0x07: "E_WRONG_PROTOCOL_VERSION",
    0x08: "E_WRONG_INTERFACE_VERSION", 0x09: "E_MALFORMED_MESSAGE",
    0x0A: "E_WRONG_MESSAGE_TYPE",
}
# SOME/IP-SD entry types per PRS_SOMEIPSD_00159.
# Note: 0x01 with ttl=0 is StopOffer; 0x06 with ttl=0 is StopSubscribe;
# 0x07 with ttl=0 is SubscribeEventgroupNack.
_SD_ENTRY_TYPES = {
    0x00: "FindService", 0x01: "OfferService",
    0x06: "SubscribeEventgroup", 0x07: "SubscribeEventgroupAck",
}
# SD option types per PRS_SOMEIPSD_00200.
_SD_OPTION_TYPES = {
    0x01: "Cfg", 0x02: "LoadBalancing",
    0x04: "IPv4Endpoint", 0x06: "IPv6Endpoint",
    0x09: "IPv4Multicast", 0x0A: "IPv6Multicast",
    0x14: "IPv4SdEndpoint", 0x16: "IPv6SdEndpoint",
}


def _looks_like_someip(buf: bytes) -> bool:
    """Heuristic: 16 B header with protocol_version==0x01 + known msg_type."""
    if len(buf) < 16:
        return False
    return buf[12] == 0x01 and buf[14] in _SOMEIP_MSG_TYPES


def _dissect_someip(payload: bytes, p: Packet) -> None:
    """Parse a SOME/IP header (and SD entries if it's an SD message)."""
    if len(payload) < 16:
        p.protocol = "SOME/IP"
        p.summary = f"SOME/IP (truncated, {len(payload)} B)"
        return
    service_id, method_id, length = struct.unpack(">HHI", payload[:8])
    client_id, session_id = struct.unpack(">HH", payload[8:12])
    proto_ver, iface_ver, msg_type, return_code = payload[12:16]
    is_event = bool(method_id & 0x8000)
    type_name = _SOMEIP_MSG_TYPES.get(msg_type, f"msg_type=0x{msg_type:02x}")
    rc_name = _SOMEIP_RETURN_CODES.get(return_code, f"rc=0x{return_code:02x}")

    base_fields = {
        "service_id": service_id, "method_id": method_id, "length": length,
        "client_id": client_id, "session_id": session_id,
        "protocol_version": proto_ver, "interface_version": iface_ver,
        "message_type": msg_type, "return_code": return_code,
    }
    is_sd = (
        service_id == 0xFFFF and method_id == 0x8100 and msg_type == 0x02
        and return_code == 0x00
    )
    if is_sd:
        p.protocol = "SOME/IP-SD"
        _dissect_sd_payload(payload[16:], p, base_fields)
        return

    p.protocol = "SOME/IP"
    p.fields = base_fields
    suffix = ""
    if msg_type in (0x80, 0x81):  # Response / Error → include return code
        suffix = f" {rc_name}"
    elif is_event and msg_type == 0x02:
        type_name = "Notification"  # already, but keeps the label crisp
    p.summary = (
        f"{type_name} svc=0x{service_id:04x} "
        f"mid=0x{method_id:04x} client=0x{client_id:04x} session=0x{session_id:04x}"
        f"{suffix}"
    )


def _dissect_sd_payload(payload: bytes, p: Packet, base_fields: dict) -> None:
    """Parse SD entries + options after the 16 B SOME/IP header."""
    if len(payload) < 8:
        p.summary = "SOME/IP-SD (truncated)"
        return
    flags = payload[0]
    entries_len = struct.unpack(">I", payload[4:8])[0]
    i = 8
    entries: list[dict] = []
    end_entries = min(i + entries_len, len(payload))
    while i + 16 <= end_entries:
        e_type = payload[i]
        idx1, idx2 = payload[i + 1], payload[i + 2]
        nopts = payload[i + 3]
        nopts1, nopts2 = (nopts >> 4) & 0x0F, nopts & 0x0F
        svc_id, inst_id = struct.unpack(">HH", payload[i + 4:i + 8])
        major = payload[i + 8]
        ttl = (payload[i + 9] << 16) | (payload[i + 10] << 8) | payload[i + 11]
        tail = payload[i + 12:i + 16]
        e: dict = {
            "type": e_type, "service_id": svc_id, "instance_id": inst_id,
            "major_version": major, "ttl": ttl,
            "index_first_options": idx1, "index_second_options": idx2,
            "n_options_first": nopts1, "n_options_second": nopts2,
        }
        if e_type in (0x00, 0x01):
            e["minor_version"] = struct.unpack(">I", tail)[0]
        elif e_type in (0x06, 0x07):
            e["counter"] = tail[1] & 0x0F
            e["eventgroup_id"] = struct.unpack(">H", tail[2:4])[0]
        entries.append(e)
        i += 16

    options: list[dict] = []
    if end_entries + 4 <= len(payload):
        opts_len = struct.unpack(">I", payload[end_entries:end_entries + 4])[0]
        j = end_entries + 4
        opts_end = min(j + opts_len, len(payload))
        while j + 3 <= opts_end:
            o_len = struct.unpack(">H", payload[j:j + 2])[0]
            o_type = payload[j + 2]
            o_end = j + 3 + o_len
            if o_type in (0x04, 0x06):  # IPv4/IPv6 endpoint
                if o_type == 0x04 and o_end - (j + 3) >= 8:
                    ip_bytes = payload[j + 4:j + 8]
                    o_proto = payload[j + 9]
                    o_port = struct.unpack(">H", payload[j + 10:j + 12])[0]
                    options.append({
                        "type": o_type, "name": _SD_OPTION_TYPES.get(o_type, "?"),
                        "ipv4": _ip(ip_bytes), "l4_proto": o_proto, "port": o_port,
                    })
                else:
                    options.append({"type": o_type, "name": _SD_OPTION_TYPES.get(o_type, "?")})
            else:
                options.append({"type": o_type, "name": _SD_OPTION_TYPES.get(o_type, f"0x{o_type:02x}")})
            j = o_end

    base_fields["sd_flags"] = flags
    base_fields["sd_entries"] = entries
    base_fields["sd_options"] = options
    p.fields = base_fields

    # Summarise the first few entries; most TC8 SD frames carry 1-2.
    parts = []
    ipv4_eps = sum(1 for o in options if o.get("type") == 0x04)
    for e in entries[:3]:
        et = e["type"]
        ttl = e["ttl"]
        name = _SD_ENTRY_TYPES.get(et, f"type=0x{et:02x}")
        # TTL=0 variants per PRS_SOMEIPSD §entries.
        if et == 0x01 and ttl == 0:
            name = "StopOfferService"
        elif et == 0x06 and ttl == 0:
            name = "StopSubscribeEventgroup"
        elif et == 0x07 and ttl == 0:
            name = "SubscribeEventgroupNack"
        head = f"{name} svc=0x{e['service_id']:04x} inst=0x{e['instance_id']:04x}"
        if et in (0x06, 0x07):
            head += f" eg=0x{e['eventgroup_id']:04x}"
        head += f" ttl={ttl}"
        parts.append(head)
    if len(entries) > 3:
        parts.append(f"+{len(entries) - 3} more")
    if ipv4_eps:
        parts.append(f"ipv4_endpoints={ipv4_eps}")
    p.summary = "SD " + " | ".join(parts) if parts else "SOME/IP-SD (no entries)"


def _dissect_udp(payload: bytes, p: Packet) -> None:
    p.protocol = "UDP"
    if len(payload) < 8:
        p.summary = "truncated"
        return
    sport, dport, length = struct.unpack(">HHH", payload[:6])
    inner = payload[8:]
    if dport in (67, 68) or sport in (67, 68):
        _dissect_dhcpv4(inner, p, sport, dport)
        return
    if dport == 30490 or sport == 30490 or _looks_like_someip(inner):
        _dissect_someip(inner, p)
        # Preserve port info alongside the SOME/IP fields.
        p.fields.setdefault("src_port", sport)
        p.fields.setdefault("dst_port", dport)
        return
    p.fields = {"src_port": sport, "dst_port": dport, "length": length}
    p.summary = f"{sport} → {dport}, len={length}"


def _dissect_tcp(payload: bytes, p: Packet) -> None:
    p.protocol = "TCP"
    if len(payload) < 20:
        p.summary = "truncated"
        return
    sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", payload[:14])
    data_off = (off_flags >> 12) * 4
    flags = off_flags & 0x01FF
    flag_names = []
    if flags & 0x002: flag_names.append("SYN")
    if flags & 0x010: flag_names.append("ACK")
    if flags & 0x001: flag_names.append("FIN")
    if flags & 0x004: flag_names.append("RST")
    if flags & 0x008: flag_names.append("PSH")
    win = struct.unpack(">H", payload[14:16])[0]
    inner = payload[data_off:] if data_off <= len(payload) else b""
    tcp_fields = {
        "src_port": sport, "dst_port": dport,
        "seq": seq, "ack": ack, "flags": "|".join(flag_names) or "—",
        "window": win,
    }

    # Peek for SOME/IP carried over TCP (ETS_037, SOMEIPSRV CHECKSUM, etc.).
    # Only attempt if payload is non-trivial and matches the SOME/IP magic.
    if inner and (sport == 30490 or dport == 30490 or _looks_like_someip(inner)):
        _dissect_someip(inner, p)
        # Tag the protocol so the row badge tells the reader it's TCP-carried.
        if p.protocol.startswith("SOME/IP"):
            p.protocol = p.protocol + "/TCP"
        # Merge TCP framing into fields without overwriting the SOME/IP dict.
        for k, v in tcp_fields.items():
            p.fields.setdefault(k, v)
        return

    p.fields = tcp_fields
    flags_str = "|".join(flag_names) or "—"
    if inner:
        p.summary = (
            f"{sport} → {dport} [{flags_str}] seq={seq} ack={ack} "
            f"win={win} len={len(inner)}"
        )
    else:
        p.summary = f"{sport} → {dport} [{flags_str}] seq={seq} ack={ack} win={win}"


def _direction(src_mac: Optional[str], dst_mac: Optional[str],
               tester_mac: Optional[str], dut_mac: Optional[str]) -> str:
    s, d = (src_mac or "").lower(), (dst_mac or "").lower()
    t, dm = (tester_mac or "").lower(), (dut_mac or "").lower()
    if t and s == t: return "tester_to_dut"
    if dm and s == dm: return "dut_to_tester"
    if t and d == t: return "dut_to_tester"
    if dm and d == dm: return "tester_to_dut"
    return "other"


def _autodetect_endpoints(packets):
    """Infer (tester_mac, dut_mac, tester_ip, dut_ip) from the capture.

    The harness's netns setup assigns random locally-administered MACs
    per veth pair, so hard-coded fixtures don't match a live capture.
    Heuristic: the two most frequent unicast src MACs are the endpoints;
    the one that emits FIRST is the tester (stimulus typically precedes
    DUT response). IPs are the first src_ip observed sourced from each
    detected MAC.
    """
    from collections import Counter
    src_counts: Counter = Counter()
    first_seen: dict = {}
    ip_for_mac: dict = {}
    for p in packets:
        mac = (p.src_mac or "").lower()
        if not mac or mac == "00:00:00:00:00:00":
            continue
        try:
            first_byte = int(mac.split(":")[0], 16)
        except ValueError:
            continue
        if first_byte & 0x01:  # multicast / broadcast bit — not an endpoint
            continue
        src_counts[mac] += 1
        if mac not in first_seen:
            first_seen[mac] = p.idx
        if p.src_ip and mac not in ip_for_mac:
            ip_for_mac[mac] = p.src_ip
    top = src_counts.most_common(2)
    if not top:
        return None, None, None, None
    if len(top) == 1:
        m = top[0][0]
        return m, None, ip_for_mac.get(m), None
    mac_a, mac_b = top[0][0], top[1][0]
    if first_seen[mac_a] <= first_seen[mac_b]:
        tester, dut = mac_a, mac_b
    else:
        tester, dut = mac_b, mac_a
    return tester, dut, ip_for_mac.get(tester), ip_for_mac.get(dut)


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
        packets.append(p)
        prev_ts = ts_us

    auto_t_mac, auto_d_mac, auto_t_ip, auto_d_ip = _autodetect_endpoints(packets)
    tester_mac = args.tester_mac or auto_t_mac
    dut_mac    = args.dut_mac    or auto_d_mac
    tester_ip  = args.tester_ip  or auto_t_ip
    dut_ip     = args.dut_ip     or auto_d_ip

    for p in packets:
        p.direction = _direction(p.src_mac, p.dst_mac, tester_mac, dut_mac)

    out = {
        "case_id": args.case_id.upper(),
        "outcome": args.outcome,
        "captured_at": args.captured_at,
        "tester_mac": tester_mac, "tester_ip": tester_ip,
        "dut_mac": dut_mac, "dut_ip": dut_ip,
        "packets": [asdict(p) for p in packets],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"wrote {len(packets)} packet(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
