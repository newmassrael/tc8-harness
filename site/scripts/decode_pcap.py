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
import sys
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
    hw_type     = struct.unpack(">H", payload[0:2])[0]
    proto_type  = struct.unpack(">H", payload[2:4])[0]
    hw_addr_len = payload[4]
    proto_addr_len = payload[5]
    opcode = struct.unpack(">H", payload[6:8])[0]
    sender_mac = _mac(payload[8:14])
    sender_ip = _ip(payload[14:18])
    target_mac = _mac(payload[18:24])
    target_ip = _ip(payload[24:28])
    # Numeric form of the proto IPs for SCXML conds that compare against
    # ``== 0`` (RFC 3927 §2.1.1 Probe sender check) — string equality
    # would never match the int literal, so surface the BE-decoded
    # uint32 alongside the dotted display form.
    sender_proto_ip_be = struct.unpack(">I", payload[14:18])[0]
    target_proto_ip_be = struct.unpack(">I", payload[24:28])[0]
    # ARP_46/_47 verify the spec-mandated hardware/protocol identity
    # bytes (HRD=1 Ethernet, HLN=6, PRO=0x0800 IPv4, PLN=4) so the
    # walker needs them on the surface to fire a concrete pass.
    p.fields = {
        "hw_type": hw_type, "proto_type": proto_type,
        "hw_addr_len": hw_addr_len, "proto_addr_len": proto_addr_len,
        "opcode": opcode, "sender_mac": sender_mac, "sender_ip": sender_ip,
        "target_mac": target_mac, "target_ip": target_ip,
        "sender_proto_ip_be": sender_proto_ip_be,
        "target_proto_ip_be": target_proto_ip_be,
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
    version      = (payload[0] >> 4) & 0x0F
    ihl          = (payload[0] & 0x0F) * 4
    total_length = struct.unpack(">H", payload[2:4])[0]
    proto        = payload[9]
    ttl          = payload[8]
    # §4.4 IPv4_FRAGMENTS / REASSEMBLY conds read these IP-header fields
    # via ``captured.ip_flags`` / ``ip_fragment_offset`` / ``ip_id``;
    # FRAGMENTS_05 verifies a non-fragment DUT egress carries DF=clear
    # MF=clear offset=0. Surface them so the walker can fire concrete.
    # IPV4_HEADER_01 / TTL_01 / VERSION_01 / 03 / 04 read total_length /
    # ttl / version off the same header.
    ip_id        = struct.unpack(">H", payload[4:6])[0]
    flags_frag   = struct.unpack(">H", payload[6:8])[0]
    ip_flags     = (flags_frag >> 13) & 0x07
    ip_frag_off  = flags_frag & 0x1FFF
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
    # Merge IP-layer fields after upper-layer dissection so the inner
    # protocol's field map already exists.
    if not hasattr(p, "fields") or p.fields is None:
        p.fields = {}
    p.fields.setdefault("ip_id", ip_id)
    p.fields.setdefault("ip_flags", ip_flags)
    p.fields.setdefault("ip_fragment_offset", ip_frag_off)
    p.fields.setdefault("ttl", ttl)
    p.fields.setdefault("total_length", total_length)
    p.fields.setdefault("version", version)
    p.fields.setdefault("ip_protocol", proto)
    p.fields.setdefault("ihl", ihl // 4)
    # IPV4_CHECKSUM_05 asserts the DUT-emitted header checksum agrees
    # with the on-wire header bytes. RFC 791 §3.1 16-bit one's complement
    # of all 16-bit words in the IP header (with the checksum field
    # itself zero-treated) MUST sum to 0xFFFF.
    s = 0
    for off in range(0, ihl, 2):
        s += struct.unpack(">H", payload[off:off+2])[0]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    p.fields.setdefault("ip_header_checksum_ok", s == 0xFFFF)
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
    fields: dict = {"type": type_, "code": code}
    # RFC 792 Echo Request/Reply (type 8/0) and RFC 792 Timestamp
    # Request/Reply (type 13/14) share an identifier+sequence header at
    # offsets 4..7. SCXML conds for §4.3 ICMPV4_TYPE_* and §4.4
    # IPv4_REASSEMBLY/FRAGMENTS read `captured.echo_id` /
    # `captured.echo_seq` against `expected.echo_id` / `expected.echo_seq`
    # (sourced from smoke-test.sh `icmpv4.echo_id` / `icmpv4.echo_seq`),
    # so surface them whenever the wire shape carries them.
    if type_ in (0, 8, 13, 14) and len(payload) >= 8:
        fields["echo_id"] = (payload[4] << 8) | payload[5]
        fields["echo_seq"] = (payload[6] << 8) | payload[7]
        # Echo payload follows the id+seq header. Lift the first 16 B
        # for surface (some conds use `echo_payload_equals(...)` against
        # a hard-coded buffer; that helper stays opaque to the generator
        # but the bytes are useful in the timeline UI).
        if type_ in (0, 8) and len(payload) > 8:
            fields["echo_payload_first16"] = payload[8:24].hex()
            fields["echo_payload_len"] = len(payload) - 8
        # Type 13/14 carry RFC 792 Timestamp triple after id+seq:
        #   originate_timestamp:  4 B (bytes 8..11)
        #   receive_timestamp:    4 B (bytes 12..15)
        #   transmit_timestamp:   4 B (bytes 16..19)
        # ICMPV4_TYPE_11 asserts the DUT's Timestamp Reply echoes the
        # tester-injected originate value and fills the two outbound
        # timestamps with kernel-clock ms-since-midnight UTC.
        if type_ in (13, 14) and len(payload) >= 20:
            fields["originate_timestamp"] = struct.unpack(">I", payload[8:12])[0]
            fields["receive_timestamp"]   = struct.unpack(">I", payload[12:16])[0]
            fields["transmit_timestamp"]  = struct.unpack(">I", payload[16:20])[0]
    # Type 12 Parameter Problem: byte 4 is the pointer field (RFC 792
    # "Parameter Problem Message" — offset into the offending IP header
    # of the byte that triggered the error). ICMPV4_ERROR_02 asserts
    # pointer == 22 (offset of IP Total Length field per spec).
    if type_ == 12 and len(payload) >= 5:
        fields["icmp_pointer"] = payload[4]
    p.fields = fields
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


# §4.8.5 Upper Tester wire protocol — see include/tc8/upper_tester_protocol.h.
# tc8-dut binds the UT server to UDP kPort = 30600; tester injects requests
# from an ephemeral src port and gets the response back on that same port.
_UT_PORT = 30600
_UT_RESPONSE_BIT = 0x80
_UT_OPCODE_NAMES = {
    0x01: "GetReceivedUdp",          0x02: "TriggerSendUdp",
    0x03: "OpenTcpSocket",           0x04: "CloseTcpSocket",
    0x05: "QueryTcpEstablished",     0x06: "SendTcpData",
    0x07: "ReceiveTcpData",          0x08: "ShutdownTcpSocketWr",
    0x09: "AbortTcpSocket",          0x0A: "SendTcpDataPattern",
    0x0B: "ReceiveTcpDataOob",       0x0C: "StartLLAutoconf",
    0x0D: "QueryLLAddress",          0x0E: "AbortLLAutoconf",
    0x0F: "StartLLAutoconfBuggy",    0x10: "StartDhcpClient",
    0x11: "QueryDhcpLease",          0x12: "AbortDhcpClient",
    0x13: "QueryTcpInfo",            0x14: "CreateUdpReceivePorts",
}
_UT_STATUS_NAMES = {
    0x00: "ok",         0x01: "malformed",     0x02: "unknown_opcode",
    0x03: "send_failed",0x04: "bind_failed",   0x05: "unknown_socket",
    0x06: "connect_failed",
}


def _dissect_ut(payload: bytes, p: Packet, src_port: int, dst_port: int) -> None:
    """Parse a UT request/response carried in a kPort UDP datagram."""
    p.protocol = "UT/UDP"
    if len(payload) < 2:
        p.summary = "UT (truncated)"
        return
    opcode_byte = payload[0]
    req_id = payload[1]
    is_response = bool(opcode_byte & _UT_RESPONSE_BIT)
    request_opcode = opcode_byte & 0x7F
    name = _UT_OPCODE_NAMES.get(request_opcode, f"op0x{request_opcode:02x}")
    fields: dict = {
        "src_port": src_port, "dst_port": dst_port,
        "ut_opcode": opcode_byte,
        "ut_request_opcode": request_opcode,
        "ut_req_id": req_id,
    }
    if not is_response:
        # Request — surface opcode + req_id only. Generator filters
        # responses-only via has_ut_response, so request body parsing
        # would just bloat the JSON.
        fields["ut_is_request"] = True
        p.fields = fields
        p.summary = f"UT req {name} (id={req_id})"
        return
    # Response — parse status + per-opcode trailer.
    fields["ut_is_response"] = True
    fields["has_ut_response"] = True
    if len(payload) < 3:
        p.fields = fields
        p.summary = f"UT resp {name} (truncated)"
        return
    status = payload[2]
    fields["ut_status"] = status
    body = payload[3:]
    bits: list[str] = []
    if request_opcode == 0x01 and body:  # GetReceivedUdp response
        received = body[0]
        fields["ut_received"] = received
        bits.append(f"received={received}")
        if received == 1 and len(body) >= 9:
            src_ip_be = struct.unpack(">I", body[1:5])[0]
            fields["ut_recv_src_ip"] = ".".join(str((src_ip_be >> s) & 0xFF) for s in (24, 16, 8, 0))
            fields["ut_recv_src_ip_be"] = src_ip_be
            fields["ut_recv_src_port"] = struct.unpack(">H", body[5:7])[0]
            fields["ut_recv_payload_len"] = struct.unpack(">H", body[7:9])[0]
            tail = body[9:9 + 16]
            fields["ut_recv_payload_first16"] = list(tail)
            bits.append(f"src={fields['ut_recv_src_ip']}:{fields['ut_recv_src_port']}")
            bits.append(f"len={fields['ut_recv_payload_len']}")
    elif request_opcode == 0x03 and body:  # OpenTcpSocket
        fields["ut_socket_id"] = body[0]
    elif request_opcode == 0x05 and body:  # QueryTcpEstablished
        fields["ut_established"] = body[0]
        bits.append(f"established={body[0]}")
    elif request_opcode in (0x07, 0x0B) and len(body) >= 2:  # ReceiveTcpData / Oob
        recv_len = struct.unpack(">H", body[:2])[0]
        fields["ut_received_payload_len"] = recv_len
        tail = body[2:2 + 16]
        fields["ut_recv_payload_first16"] = list(tail)
        bits.append(f"recv_len={recv_len}")
    elif request_opcode == 0x0D and len(body) >= 4:  # QueryLLAddress
        ip_be = struct.unpack(">I", body[:4])[0]
        fields["ut_linklocal_ip_be"] = ip_be
        fields["ut_linklocal_ip"] = ".".join(str((ip_be >> s) & 0xFF) for s in (24, 16, 8, 0))
        bits.append(f"addr={fields['ut_linklocal_ip']}")
    elif request_opcode == 0x11 and len(body) >= 4:  # QueryDhcpLease
        ip_be = struct.unpack(">I", body[:4])[0]
        fields["ut_lease_ip_be"] = ip_be
        fields["ut_lease_ip"] = ".".join(str((ip_be >> s) & 0xFF) for s in (24, 16, 8, 0))
        bits.append(f"lease={fields['ut_lease_ip']}")
    elif request_opcode == 0x13 and len(body) >= 10:  # QueryTcpInfo
        state = body[0]
        rto_us = struct.unpack(">I", body[1:5])[0]
        retx = body[5]
        unacked = struct.unpack(">I", body[6:10])[0]
        fields["ut_tcpi_state"] = state
        fields["ut_tcpi_rto_us"] = rto_us
        fields["ut_tcpi_retransmits"] = retx
        fields["ut_tcpi_unacked"] = unacked
        bits.append(f"state={state} rto={rto_us}us retx={retx} unacked={unacked}")
    elif request_opcode == 0x14 and body:  # CreateUdpReceivePorts
        fields["ut_create_actual_count"] = body[0]
        bits.append(f"actual={body[0]}")
    p.fields = fields
    status_name = _UT_STATUS_NAMES.get(status, f"status=0x{status:02x}")
    trailer = (" " + " ".join(bits)) if bits else ""
    p.summary = f"UT resp {name} {status_name}{trailer}"


def _dissect_dhcpv4(payload: bytes, p: Packet, src_port: int, dst_port: int) -> None:
    """Parse BOOTP + DHCP option 53 (Message Type) from a UDP 67/68 payload."""
    p.protocol = "DHCPv4"
    # BOOTP fixed part is 236 B + magic cookie (4 B) before options.
    if len(payload) < 240:
        p.summary = f"DHCPv4 (truncated, {len(payload)} B)"
        return
    op = payload[0]
    htype = payload[1]
    hlen = payload[2]
    hops = payload[3]
    xid = struct.unpack(">I", payload[4:8])[0]
    secs = struct.unpack(">H", payload[8:10])[0]
    bootp_flags = struct.unpack(">H", payload[10:12])[0]
    ciaddr = _ip(payload[12:16])
    yiaddr = _ip(payload[16:20])
    siaddr = _ip(payload[20:24])
    giaddr = _ip(payload[24:28])
    chaddr = _mac(payload[28:34])
    cookie = payload[236:240]
    msg_type = None
    end_option_seen = False
    options_seen: list[int] = []
    if cookie == b"\x63\x82\x53\x63":
        i = 240
        while i < len(payload):
            opt = payload[i]
            if opt == 255:  # End
                end_option_seen = True
                break
            if opt == 0:    # Pad
                i += 1
                continue
            options_seen.append(opt)
            if i + 1 >= len(payload):
                break
            ln = payload[i + 1]
            val = payload[i + 2:i + 2 + ln]
            if opt == 53 and ln >= 1 and msg_type is None:
                msg_type = val[0]
            i += 2 + ln
    name = _DHCPV4_MSG_TYPES.get(msg_type) if msg_type is not None else None
    p.fields = {
        "src_port": src_port, "dst_port": dst_port,
        "op": op, "htype": htype, "hlen": hlen, "hops": hops,
        "xid": xid, "secs": secs, "bootp_flags": bootp_flags,
        "ciaddr": ciaddr, "yiaddr": yiaddr, "siaddr": siaddr, "giaddr": giaddr,
        "chaddr": chaddr,
        "dhcp_msg_type": msg_type,
        # §4.7 DHCPv4 conformance reads these for the SCXML guards:
        #   * CONSTRUCTING_MESSAGES_01 — `ends_with_end_option()`
        #   * CONSTRUCTING_MESSAGES_05 — `flags_reserved_bits_zero()`
        #     (the BOOTP Flags field's bits 14..0 are reserved-must-be-0)
        #   * INITIALIZATION_ALLOCATION_02 — `ciaddr_is_zero()` (Discover
        #     must have ciaddr=0.0.0.0 per RFC 2131 §4.3.1 step 1).
        "dhcp_end_option_seen": end_option_seen,
        "dhcp_options_seen": options_seen,
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
# SD option types per PRS_SOMEIPSD §4.2.2 / SWS_SD §7.3 Table 11.
# Matches the namespace ``::tc8::sd_option_type::k*`` in
# ``src/sce_integration/someip_captured.h`` so SCXML conds that filter
# by ``sd_first_option_with_l4(kIpv4Multicast, kUdp)`` see the same
# integer the spec assigns.
_SD_OPTION_TYPES = {
    0x01: "Cfg", 0x02: "LoadBalancing",
    0x04: "IPv4Endpoint", 0x06: "IPv6Endpoint",
    0x14: "IPv4Multicast", 0x16: "IPv6Multicast",
    0x24: "IPv4SdEndpoint", 0x26: "IPv6SdEndpoint",
}
# Option types whose wire payload is the 8-byte IPv4 endpoint shape
# (1B Reserved + 4B IPv4 + 1B Reserved + 1B L4 + 2B Port). The Endpoint /
# Multicast / SD Endpoint variants differ only in semantics; the bytes
# they carry are identical, so the same parse path covers all three.
_SD_IPV4_OPTION_TYPES = (0x04, 0x14, 0x24)


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
    # 24-bit Reserved field per PRS_SOMEIPSD §4.2 SD message layout —
    # MUST be 0x000000. Surface so SOMEIPSRV_FORMAT_10's conformance
    # cond can compare against the wire value rather than UNKNOWN.
    sd_reserved = (payload[1] << 16) | (payload[2] << 8) | payload[3]
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
            entry: dict = {
                "type": o_type,
                "name": _SD_OPTION_TYPES.get(o_type, f"0x{o_type:02x}"),
                "length": o_len,
            }
            # Per PRS_SOMEIPSD §4.2.2 IPv4 endpoint / multicast /
            # sd-endpoint options share the same 8-byte wire payload
            # (reserved+ipv4+reserved+l4_proto+port). Surface every
            # field the SCXML grammar checks against — including the
            # spec-MUST reserved bytes so conformance asserts can
            # observe wire reality, not a synthesised value.
            if o_type in _SD_IPV4_OPTION_TYPES and o_end - (j + 3) >= 8:
                entry["reserved1"] = payload[j + 3]
                entry["ipv4"] = _ip(payload[j + 4:j + 8])
                entry["reserved2"] = payload[j + 8]
                entry["l4_proto"] = payload[j + 9]
                entry["port"] = struct.unpack(">H", payload[j + 10:j + 12])[0]
            options.append(entry)
            j = o_end

    base_fields["sd_flags"] = flags
    base_fields["sd_reserved"] = sd_reserved
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
    sport, dport, length, cksum = struct.unpack(">HHHH", payload[:8])
    inner = payload[8:]
    if dport in (67, 68) or sport in (67, 68):
        _dissect_dhcpv4(inner, p, sport, dport)
        p.fields.setdefault("checksum", cksum)
        return
    if dport == 30490 or sport == 30490 or _looks_like_someip(inner):
        _dissect_someip(inner, p)
        # Preserve port info alongside the SOME/IP fields.
        p.fields.setdefault("src_port", sport)
        p.fields.setdefault("dst_port", dport)
        p.fields.setdefault("checksum", cksum)
        return
    if sport == _UT_PORT or dport == _UT_PORT:
        _dissect_ut(inner, p, sport, dport)
        p.fields.setdefault("checksum", cksum)
        return
    p.fields = {
        "src_port": sport, "dst_port": dport, "length": length,
        "checksum": cksum,
    }
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
    win, cksum, urg_ptr = struct.unpack(">HHH", payload[14:20])
    inner = payload[data_off:] if data_off <= len(payload) else b""
    payload_len = max(0, len(payload) - data_off)
    tcp_fields = {
        "src_port": sport, "dst_port": dport,
        "seq": seq, "ack": ack, "flags": "|".join(flag_names) or "—",
        "window": win,
        "checksum": cksum, "urgent_pointer": urg_ptr,
        "data_offset": data_off // 4,
        # §4.8.6.2 TCP_CHECKSUM_03 / §4.8.6.1 HEADER_01 cond
        # ``captured.payload_len > 0`` distinguishes the spec-asserted
        # DATA segment from the handshake ACK that precedes it.
        "payload_len": payload_len,
    }
    # RFC 793 §3.1 TCP options — only kind=2 (Maximum Segment Size) is
    # surfaced today; §4.8.6.9 MSS_OPTIONS_11/_12 read
    # ``captured.mss`` against ``> 0`` / ``!= 536`` (RFC 1122 default).
    # Options live between byte 20 and the start of payload at
    # ``data_off``. Walker uses 0 as the "no MSS option" sentinel
    # (matches the C++ ``TcpCaptured::mss = 0`` default).
    if data_off > 20 and data_off <= len(payload):
        opts = payload[20:data_off]
        i = 0
        while i < len(opts):
            kind = opts[i]
            if kind == 0:   # End of Options
                break
            if kind == 1:   # NOP
                i += 1
                continue
            if i + 1 >= len(opts):
                break
            olen = opts[i + 1]
            if olen < 2 or i + olen > len(opts):
                break
            if kind == 2 and olen == 4:
                tcp_fields["mss"] = struct.unpack(
                    ">H", opts[i + 2:i + 4]
                )[0]
            i += olen

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
    ap.add_argument("--trace-json", type=Path,
                    help="Path to harness-emitted transition trace JSON "
                         "(Evidence Export). Merged into the output under "
                         "``captured_trace``. Missing path is silently "
                         "ignored — pre-trace pcaps stay backward "
                         "compatible with the site walker's fallback path.")
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

    # Evidence Export — merge the harness-emitted transition trace if the
    # sidecar exists. The harness writes <pcap>.trace.json alongside
    # every retained .pcap (see src/cli/test_command.cpp::execute), so
    # CI just passes ``--trace-json "${pcap%.pcap}.trace.json"``. Older
    # pcaps without a sidecar fall through to the site walker's
    # backward-compat cond-loop path.
    if args.trace_json and args.trace_json.exists():
        try:
            out["captured_trace"] = json.loads(
                args.trace_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"warning: malformed trace JSON {args.trace_json}: {exc}",
                  file=sys.stderr)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, ensure_ascii=False),
                        encoding="utf-8")
    print(f"wrote {len(packets)} packet(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
