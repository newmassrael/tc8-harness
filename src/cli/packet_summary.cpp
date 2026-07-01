#include "cli/packet_summary.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "sce_integration/captured_trace.h"   // tc8::sce::ipv4ToDotted / macToHex
#include "someip/protocol.h"                  // tc8::someip::MessageType / ReturnCode / isSdMessageId
#include "someip/sd_decode.h"                 // SdDecoded + parseSdInto + sd_entry_type/sd_option_type (neutral SD decode)
#include "tc8/upper_tester_protocol.h"        // tc8::ut::Opcode / decodeResponse / kPort / kStatus*

namespace tc8::cli {

namespace {

// MAC and captured-uint32 (octet 0 in the low byte) dotted-quad formatting
// reuse the harness SSOT cores tc8::sce::macToHex / tc8::sce::ipv4ToDotted, so
// this layer holds no second copy of that byte ordering.
using ::tc8::sce::ipv4ToDotted;
using ::tc8::sce::macToHex;

std::string hex4(std::uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%04x", v);
    return std::string(buf);
}

std::string hex8(std::uint32_t v) {
    char buf[12];
    std::snprintf(buf, sizeof(buf), "%08x", v);
    return std::string(buf);
}

std::string join(const std::vector<std::string> &parts, const char *sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out.append(sep);
        out.append(parts[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Display name tables (presentation only; the numeric values are the wire
// constants). Mirror the labels site/scripts/decode_pcap.py used so the
// rendered timeline text is unchanged.
// ---------------------------------------------------------------------------

// Value->meaning for both of these is the shared SSOT enum
// (src/someip/protocol.h, owned by neither builder nor parser); this only
// attaches a display string. A wire value the harness does not model (e.g. the
// *Ack message-type family) matches no enumerator and falls through to the
// caller's numeric form.
const char *someipMsgTypeName(std::uint8_t mt) {
    using MT = ::tc8::someip::MessageType;
    switch (static_cast<MT>(mt)) {
        case MT::REQUEST:              return "Request";
        case MT::REQUEST_NO_RETURN:    return "RequestNoReturn";
        case MT::NOTIFICATION:         return "Notification";
        case MT::RESPONSE:             return "Response";
        case MT::ERROR:                return "Error";
        case MT::TP_REQUEST:           return "TP-Request";
        case MT::TP_REQUEST_NO_RETURN: return "TP-RequestNoReturn";
        case MT::TP_NOTIFICATION:      return "TP-Notification";
        case MT::TP_RESPONSE:          return "TP-Response";
        case MT::TP_ERROR:             return "TP-Error";
    }
    return nullptr;
}

const char *someipReturnCodeName(std::uint8_t rc) {
    using RC = ::tc8::someip::ReturnCode;
    switch (static_cast<RC>(rc)) {
        case RC::E_OK:                     return "E_OK";
        case RC::E_NOT_OK:                 return "E_NOT_OK";
        case RC::E_UNKNOWN_SERVICE:        return "E_UNKNOWN_SERVICE";
        case RC::E_UNKNOWN_METHOD:         return "E_UNKNOWN_METHOD";
        case RC::E_NOT_READY:              return "E_NOT_READY";
        case RC::E_NOT_REACHABLE:          return "E_NOT_REACHABLE";
        case RC::E_TIMEOUT:                return "E_TIMEOUT";
        case RC::E_WRONG_PROTOCOL_VERSION: return "E_WRONG_PROTOCOL_VERSION";
        case RC::E_WRONG_INTERFACE_VERSION:return "E_WRONG_INTERFACE_VERSION";
        case RC::E_MALFORMED_MESSAGE:      return "E_MALFORMED_MESSAGE";
        case RC::E_WRONG_MESSAGE_TYPE:     return "E_WRONG_MESSAGE_TYPE";
    }
    return nullptr;
}

const char *sdEntryTypeName(std::uint8_t et) {
    namespace et_ns = ::tc8::sd_entry_type;  // SD entry-type value SSOT
    if (et == et_ns::kFindService)            return "FindService";
    if (et == et_ns::kOfferService)           return "OfferService";
    if (et == et_ns::kSubscribeEventgroup)    return "SubscribeEventgroup";
    if (et == et_ns::kSubscribeEventgroupAck) return "SubscribeEventgroupAck";
    return nullptr;
}

const char *icmpTypeName(std::uint8_t t) {
    switch (t) {
        case 0:  return "Echo Reply";
        case 3:  return "Destination Unreachable";
        case 4:  return "Source Quench";
        case 5:  return "Redirect";
        case 8:  return "Echo Request";
        case 9:  return "Router Advertisement";
        case 10: return "Router Solicitation";
        case 11: return "Time Exceeded";
        case 12: return "Parameter Problem";
        case 13: return "Timestamp Request";
        case 14: return "Timestamp Reply";
        case 15: return "Information Request";
        case 16: return "Information Reply";
        case 17: return "Address Mask Request";
        case 18: return "Address Mask Reply";
        default: return nullptr;
    }
}

const char *icmpDuCodeName(std::uint8_t c) {
    switch (c) {
        case 0: return "net unreachable";
        case 1: return "host unreachable";
        case 2: return "protocol unreachable";
        case 3: return "port unreachable";
        case 4: return "fragmentation needed";
        case 5: return "source route failed";
        default: return nullptr;
    }
}

const char *dhcpMsgTypeName(std::uint8_t mt) {
    switch (mt) {
        case 1: return "Discover";
        case 2: return "Offer";
        case 3: return "Request";
        case 4: return "Decline";
        case 5: return "Ack";
        case 6: return "Nak";
        case 7: return "Release";
        case 8: return "Inform";
        default: return nullptr;
    }
}

// UT opcode display name keyed on the wire opcode (the tc8::ut::Opcode enum is
// the value SSOT; the strings are the human labels).
std::string utOpcodeName(std::uint8_t op) {
    using namespace ::tc8::ut;
    switch (op) {
        case OpGetReceivedUdp:        return "GetReceivedUdp";
        case OpTriggerSendUdp:        return "TriggerSendUdp";
        case OpOpenTcpSocket:         return "OpenTcpSocket";
        case OpCloseTcpSocket:        return "CloseTcpSocket";
        case OpQueryTcpEstablished:   return "QueryTcpEstablished";
        case OpSendTcpData:           return "SendTcpData";
        case OpReceiveTcpData:        return "ReceiveTcpData";
        case OpShutdownTcpSocketWr:   return "ShutdownTcpSocketWr";
        case OpAbortTcpSocket:        return "AbortTcpSocket";
        case OpSendTcpDataPattern:    return "SendTcpDataPattern";
        case OpReceiveTcpDataOob:     return "ReceiveTcpDataOob";
        case OpStartLLAutoconf:       return "StartLLAutoconf";
        case OpQueryLLAddress:        return "QueryLLAddress";
        case OpAbortLLAutoconf:       return "AbortLLAutoconf";
        case OpStartLLAutoconfBuggy:  return "StartLLAutoconfBuggy";
        case OpStartDhcpClient:       return "StartDhcpClient";
        case OpQueryDhcpLease:        return "QueryDhcpLease";
        case OpAbortDhcpClient:       return "AbortDhcpClient";
        case OpQueryTcpInfo:          return "QueryTcpInfo";
        case OpCreateUdpReceivePorts: return "CreateUdpReceivePorts";
        default: {
            char buf[12];
            std::snprintf(buf, sizeof(buf), "op0x%02x", op);
            return std::string(buf);
        }
    }
}

std::string utStatusName(std::uint8_t st) {
    using namespace ::tc8::ut;
    switch (st) {
        case kStatusOk:            return "ok";
        case kStatusMalformed:     return "malformed";
        case kStatusUnknownOpcode: return "unknown_opcode";
        case kStatusSendFailed:    return "send_failed";
        case kStatusBindFailed:    return "bind_failed";
        case kStatusUnknownSocket: return "unknown_socket";
        case kStatusConnectFailed: return "connect_failed";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "status=0x%02x", st);
            return std::string(buf);
        }
    }
}

std::string tcpFlagsStr(std::uint8_t flags) {
    std::vector<std::string> names;
    if (flags & 0x02u) names.emplace_back("SYN");
    if (flags & 0x10u) names.emplace_back("ACK");
    if (flags & 0x01u) names.emplace_back("FIN");
    if (flags & 0x04u) names.emplace_back("RST");
    if (flags & 0x08u) names.emplace_back("PSH");
    return names.empty() ? std::string("\xE2\x80\x94") /* em dash */ : join(names, "|");
}

}  // namespace

// ---------------------------------------------------------------------------
// Per-protocol human summary lines (mirror decode_pcap.py's _dissect_*).
// ---------------------------------------------------------------------------

std::string arpSummary(const ::tc8::ArpFrame &f) {
    const std::string sender_ip = ipv4ToDotted(f.sender_proto_ip);
    const std::string target_ip = ipv4ToDotted(f.target_proto_ip);
    const std::string sender_mac = macToHex(f.sender_hw);
    if (f.opcode == 1) {
        return "Who has " + target_ip + "? Tell " + sender_ip + " (sender_mac=" + sender_mac + ")";
    }
    if (f.opcode == 2) {
        return sender_ip + " is at " + sender_mac;
    }
    return "opcode=" + std::to_string(f.opcode);
}

std::string icmpSummary(const ::tc8::Icmpv4Frame &f) {
    const char *name = icmpTypeName(f.type);
    if (f.type == 3) {  // Destination Unreachable — code matters
        const char *cn = icmpDuCodeName(f.code);
        const std::string code_name = cn ? std::string(cn) : ("code=" + std::to_string(f.code));
        return name ? (std::string(name) + ": " + code_name)
                    : ("type=" + std::to_string(f.type) + " code=" + std::to_string(f.code));
    }
    if (name != nullptr) {
        return f.code == 0 ? std::string(name)
                           : (std::string(name) + " (code=" + std::to_string(f.code) + ")");
    }
    return "type=" + std::to_string(f.type) + " code=" + std::to_string(f.code);
}

std::string dhcpSummary(const ::tc8::Dhcpv4Frame &f) {
    const char *name = dhcpMsgTypeName(f.message_type);
    const std::string chaddr = macToHex(f.chaddr.data());
    if (name != nullptr) {
        return std::string("DHCPv4 ") + name + " xid=0x" + hex8(f.xid) + " chaddr=" + chaddr;
    }
    std::string op_name = f.op == 1 ? "BOOTREQUEST"
                        : f.op == 2 ? "BOOTREPLY"
                                    : ("op=" + std::to_string(f.op));
    return "DHCPv4 " + op_name + " xid=0x" + hex8(f.xid);
}

std::string tcpSummary(const ::tc8::TcpFrame &f) {
    const std::string flags = tcpFlagsStr(f.flags);
    std::string s = std::to_string(f.src_port) + " \xE2\x86\x92 " + std::to_string(f.dst_port) +
                    " [" + flags + "] seq=" + std::to_string(f.seq_num) +
                    " ack=" + std::to_string(f.ack_num) + " win=" + std::to_string(f.window);
    if (f.payload_len > 0) {
        s += " len=" + std::to_string(f.payload_len);
    }
    return s;
}

std::string udpSummary(const ::tc8::UdpFrame &f) {
    return std::to_string(f.src_port) + " \xE2\x86\x92 " + std::to_string(f.dst_port) +
           ", len=" + std::to_string(f.length);
}

std::string someipSummary(const ::tc8::SomeIpFrame &f) {
    const char *tn = someipMsgTypeName(f.message_type);
    char mt_buf[20];
    if (tn == nullptr) {
        std::snprintf(mt_buf, sizeof(mt_buf), "msg_type=0x%02x", f.message_type);
    }
    std::string suffix;
    const auto mt = static_cast<::tc8::someip::MessageType>(f.message_type);
    if (mt == ::tc8::someip::MessageType::RESPONSE || mt == ::tc8::someip::MessageType::ERROR) {
        const char *rc = someipReturnCodeName(f.return_code);
        char rc_buf[16];
        if (rc == nullptr) {
            std::snprintf(rc_buf, sizeof(rc_buf), "rc=0x%02x", f.return_code);
        }
        suffix = std::string(" ") + (rc ? rc : rc_buf);
    }
    return std::string(tn ? tn : mt_buf) + " svc=0x" + hex4(f.service_id) + " mid=0x" +
           hex4(f.method_id) + " client=0x" + hex4(f.client_id) + " session=0x" +
           hex4(f.session_id) + suffix;
}

// SOME/IP-SD entry/option summary, decoded through the authoritative
// SomeIpCaptured SD parser (someip_captured.h expands someip_sd_wire.def).
std::string sdSummary(const ::tc8::SomeIpFrame &f) {
    // Decode through the neutral SD leaf (someip/sd_decode.h) — the SAME decoder
    // the verdict path uses — so presentation does not depend up on the verdict
    // layer and the wire is decoded once (docs/tech-debt.md TD-06/TD-05).
    ::tc8::SdDecoded d{};
    ::tc8::parseSdInto(d, f.payload_data, f.payload_len);

    std::vector<std::string> parts;
    // "+N more" and the endpoint count are taken from the uncapped on-wire
    // totals (TD-09) so a frame with more entries/options than the parse cap
    // (kMaxSdEntries/kMaxSdOptions) is not silently undercounted on the site.
    const std::size_t shown = std::min<std::size_t>(d.sd_entry_count, 3);
    for (std::size_t i = 0; i < shown; ++i) {
        const auto &e = d.sd_entries[i];
        const char *base = sdEntryTypeName(e.type);
        namespace et_ns = ::tc8::sd_entry_type;
        std::string name;
        if (e.type == et_ns::kOfferService && e.ttl == 0) {
            name = "StopOfferService";
        } else if (e.type == et_ns::kSubscribeEventgroup && e.ttl == 0) {
            name = "StopSubscribeEventgroup";
        } else if (e.type == et_ns::kSubscribeEventgroupAck && e.ttl == 0) {
            name = "SubscribeEventgroupNack";
        } else if (base != nullptr) {
            name = base;
        } else {
            char tbuf[12];
            std::snprintf(tbuf, sizeof(tbuf), "type=0x%02x", e.type);
            name = tbuf;
        }
        std::string head = name + " svc=0x" + hex4(e.service_id) + " inst=0x" + hex4(e.instance_id);
        if (e.type == et_ns::kSubscribeEventgroup || e.type == et_ns::kSubscribeEventgroupAck) {
            head += " eg=0x" + hex4(e.eventgroup_id);
        }
        head += " ttl=" + std::to_string(e.ttl);
        parts.push_back(std::move(head));
    }
    if (d.sd_entry_count_wire > shown) {
        parts.push_back("+" + std::to_string(d.sd_entry_count_wire - shown) + " more");
    }
    if (d.sd_ipv4_endpoint_count_wire != 0) {
        parts.push_back("ipv4_endpoints=" + std::to_string(d.sd_ipv4_endpoint_count_wire));
    }
    return parts.empty() ? std::string("SOME/IP-SD (no entries)") : ("SD " + join(parts, " | "));
}

// UT request/response carried in a kPort UDP datagram (mirror _dissect_ut).
// Decoded through the shared tc8::ut::decodeResponse (the single owner of the
// response wire offsets, docs/tech-debt.md TD-06) — the same decoder the
// verdict path (udp_captured.h) consumes. IP fields come back in network byte
// order and format through the ipv4ToDotted SSOT core.
std::string utSummary(const std::uint8_t *payload, std::uint32_t len) {
    const ::tc8::ut::UtResponse r = ::tc8::ut::decodeResponse(payload, len);
    if (!r.present) return "UT (truncated)";
    const std::string name = utOpcodeName(r.request_opcode);

    if (!r.is_response) {
        return "UT req " + name + " (id=" + std::to_string(r.req_id) + ")";
    }
    if (!r.has_status) {
        return "UT resp " + name + " (truncated)";
    }
    std::vector<std::string> bits;
    switch (r.request_opcode) {
        case ::tc8::ut::OpGetReceivedUdp:
            if (r.received_valid) {
                bits.push_back("received=" + std::to_string(r.received));
                if (r.recv_trailer_valid) {
                    bits.push_back("src=" + ipv4ToDotted(r.recv_src_ip) + ":" +
                                   std::to_string(r.recv_src_port));
                    bits.push_back("len=" + std::to_string(r.recv_payload_len));
                }
            }
            break;
        case ::tc8::ut::OpQueryTcpEstablished:
            if (r.established_valid) bits.push_back("established=" + std::to_string(r.established));
            break;
        case ::tc8::ut::OpReceiveTcpData:
        case ::tc8::ut::OpReceiveTcpDataOob:
            if (r.recv_len_valid) bits.push_back("recv_len=" + std::to_string(r.recv_len));
            break;
        case ::tc8::ut::OpQueryLLAddress:
            if (r.ll_address_valid) bits.push_back("addr=" + ipv4ToDotted(r.ll_address));
            break;
        case ::tc8::ut::OpQueryDhcpLease:
            if (r.dhcp_lease_valid) bits.push_back("lease=" + ipv4ToDotted(r.dhcp_lease));
            break;
        case ::tc8::ut::OpQueryTcpInfo:
            if (r.tcp_info_valid) {
                bits.push_back("state=" + std::to_string(r.tcp_state));
                bits.push_back("rto=" + std::to_string(r.tcp_rto_us) + "us");
                bits.push_back("retx=" + std::to_string(r.tcp_retransmits));
                bits.push_back("unacked=" + std::to_string(r.tcp_unacked));
            }
            break;
        case ::tc8::ut::OpCreateUdpReceivePorts:
            if (r.create_count_valid) bits.push_back("actual=" + std::to_string(r.create_actual_count));
            break;
        default:
            break;
    }
    const std::string status_name = utStatusName(r.status);
    const std::string trailer = bits.empty() ? std::string() : (" " + join(bits, " "));
    return "UT resp " + name + " " + status_name + trailer;
}

bool someipIsSd(const ::tc8::SomeIpFrame &f) {
    // The SD Message ID (service 0xFFFF / method 0x8100) routes through the
    // someip::isSdMessageId SSOT; the type/code parts route through the SSOT
    // enums. A well-formed SD message is a NOTIFICATION with E_OK.
    return ::tc8::someip::isSdMessageId(f.service_id, f.method_id) &&
           static_cast<::tc8::someip::MessageType>(f.message_type) ==
               ::tc8::someip::MessageType::NOTIFICATION &&
           static_cast<::tc8::someip::ReturnCode>(f.return_code) ==
               ::tc8::someip::ReturnCode::E_OK;
}

Candidate makeCandidate(const ::tc8::CapturedEvent &ev) {
    Candidate c;
    std::visit(
        [&c](const auto &f) {
            using T = std::decay_t<decltype(f)>;
            if constexpr (std::is_same_v<T, ::tc8::ArpFrame>) {
                c.prio = 1;
                c.protocol = "ARP";
                c.summary = arpSummary(f);
            } else if constexpr (std::is_same_v<T, ::tc8::Ipv4Frame>) {
                c.prio = 2;
                c.protocol = "IPv4 proto=" + std::to_string(f.protocol);
                c.summary = std::to_string(f.total_length) + " B";
                c.src_ip = f.src_addr;
                c.dst_ip = f.dst_addr;
            } else if constexpr (std::is_same_v<T, ::tc8::Icmpv4Frame>) {
                c.prio = 3;
                c.protocol = "ICMPv4";
                c.summary = icmpSummary(f);
                c.src_ip = f.src_ip;
                c.dst_ip = f.dst_ip;
            } else if constexpr (std::is_same_v<T, ::tc8::TcpFrame>) {
                c.prio = 3;
                c.protocol = "TCP";
                c.summary = tcpSummary(f);
                c.src_ip = f.src_ip;
                c.dst_ip = f.dst_ip;
            } else if constexpr (std::is_same_v<T, ::tc8::UdpFrame>) {
                c.prio = 3;
                c.src_ip = f.src_ip;
                c.dst_ip = f.dst_ip;
                if (f.src_port == ::tc8::ut::kPort || f.dst_port == ::tc8::ut::kPort) {
                    c.protocol = "UT/UDP";
                    c.summary = utSummary(f.payload_data, f.payload_len);
                } else if (::tc8::isDhcpPortPair(f.src_port, f.dst_port)) {
                    // A datagram on the DHCP port pair that the pipeline did NOT
                    // raise as a Dhcpv4Frame is a BOOTP body too short to reach
                    // the magic cookie (< 240 B, TD-09) — label it truncated
                    // rather than showing it as plain UDP. A well-formed DHCP
                    // datagram also emits a prio-4 Dhcpv4Frame that outranks this.
                    c.protocol = "DHCPv4";
                    c.summary = "DHCPv4 (truncated, " + std::to_string(f.payload_len) + " B)";
                } else {
                    c.protocol = "UDP";
                    c.summary = udpSummary(f);
                }
            } else if constexpr (std::is_same_v<T, ::tc8::Dhcpv4Frame>) {
                c.prio = 4;
                c.protocol = "DHCPv4";
                c.summary = dhcpSummary(f);
                c.src_ip = f.src_ip;
                c.dst_ip = f.dst_ip;
            } else if constexpr (std::is_same_v<T, ::tc8::SomeIpFrame>) {
                c.prio = 5;
                const bool is_sd = someipIsSd(f);
                c.protocol = is_sd ? "SOME/IP-SD" : "SOME/IP";
                if (f.is_tcp) c.protocol += "/TCP";
                c.summary = is_sd ? sdSummary(f) : someipSummary(f);
                c.src_ip = f.src_ip;
                c.dst_ip = f.dst_ip;
            }
        },
        ev);
    return c;
}

FrameView chooseFrameView(const std::vector<Candidate> &candidates,
                          std::uint16_t ethertype, std::uint32_t caplen) {
    FrameView v;
    const Candidate *best = nullptr;
    for (const auto &cand : candidates) {
        if (best == nullptr || cand.prio > best->prio) best = &cand;
    }
    if (best != nullptr) {
        v.protocol = best->protocol;
        v.summary = best->summary;
        v.src_ip = best->src_ip;
        v.dst_ip = best->dst_ip;
        return v;
    }
    if (caplen < 14u) {
        // Too short to carry an Ethernet header (ethertype was never read).
        // Leave the UNKNOWN / "" defaults rather than synthesize "ETH 0x0000".
        return v;
    }
    if (ethertype == 0x0806) {
        v.protocol = "ARP";
        v.summary = "truncated ARP";
    } else if (ethertype == 0x0800) {
        v.protocol = "IPv4";
        v.summary = "truncated";
    } else {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "ETH 0x%04x", ethertype);
        v.protocol = buf;
        v.summary = std::to_string(caplen) + " B";
    }
    return v;
}

}  // namespace tc8::cli
