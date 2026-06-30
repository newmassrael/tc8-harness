#include "cli/decode_pcap_command.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <pcap/pcap.h>

#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"

#include "capture/pcap_source.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/captured_trace.h"   // tc8::sce::appendJsonEscaped (JSON string escape SSOT)
#include "sce_integration/someip_captured.h"  // SomeIpCaptured + fillSomeIpCapturedFromFrame + sd_option_type
#include "someip/protocol.h"                  // tc8::someip::MessageType / ReturnCode (shared value SSOT)

namespace tc8::cli {

namespace {

// ---------------------------------------------------------------------------
// Formatting primitives. MAC and captured-uint32 (octet 0 in the low byte)
// dotted-quad formatting reuses the harness SSOT cores tc8::sce::macToHex /
// tc8::sce::ipv4ToDotted (the same layout appendMacJson/appendIpv4Json emit),
// so this command holds no second copy of that byte ordering.
// ---------------------------------------------------------------------------
using ::tc8::sce::ipv4ToDotted;
using ::tc8::sce::macToHex;

// Big-endian uint32 (wire order, octet 0 = high byte) -> dotted quad. Distinct
// from ipv4ToDotted's NBO-in-low-byte convention: the Upper-Tester response
// trailers carry their IPs big-endian on the wire, and the harness has no
// existing BE-dotted formatter, so this is not a duplicate of the SSOT core.
std::string ipv4FromBe(std::uint32_t be) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>((be >> 24) & 0xFFu),
                  static_cast<unsigned>((be >> 16) & 0xFFu),
                  static_cast<unsigned>((be >> 8) & 0xFFu),
                  static_cast<unsigned>(be & 0xFFu));
    return std::string(buf);
}

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

std::uint16_t be16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((static_cast<unsigned>(p[0]) << 8) | p[1]);
}

std::uint32_t be32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void appendJsonString(std::string &out, std::string_view s) {
    out.push_back('"');
    ::tc8::sce::appendJsonEscaped(out, s);
    out.push_back('"');
}

std::string join(const std::vector<std::string> &parts, const char *sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out.append(sep);
        out.append(parts[i]);
    }
    return out;
}

// Minimal structural well-formedness check for the harness trace sidecar (the
// harness avoids a JSON library, so this is not a full RFC 8259 parser). It
// confirms `s` is a single brace-balanced JSON object with well-formed string
// literals — enough to guarantee that splicing it in as a value keeps the
// surrounding PacketCapture document parseable. Its job is to catch the
// realistic corruption (a truncated or non-JSON sidecar from an interrupted
// write), so a malformed trace is dropped with a warning rather than silently
// emitting an invalid artifact (the retired decode_pcap.py validated via
// json.loads for the same reason).
bool isWellFormedJsonObject(std::string_view s) {
    auto isws = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    std::size_t i = 0;
    const std::size_t n = s.size();
    while (i < n && isws(s[i])) ++i;
    if (i >= n || s[i] != '{') return false;
    int depth = 0;
    bool in_str = false;
    bool escaped = false;
    bool closed = false;
    for (; i < n; ++i) {
        const char c = s[i];
        if (closed) {
            if (!isws(c)) return false;  // trailing content after the top-level object
            continue;
        }
        if (in_str) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') {
            in_str = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
            if (depth == 0) closed = true;
        }
    }
    return closed && !in_str && depth == 0;
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

std::string tcpFlagsStr(std::uint8_t flags) {
    std::vector<std::string> names;
    if (flags & 0x02u) names.emplace_back("SYN");
    if (flags & 0x10u) names.emplace_back("ACK");
    if (flags & 0x01u) names.emplace_back("FIN");
    if (flags & 0x04u) names.emplace_back("RST");
    if (flags & 0x08u) names.emplace_back("PSH");
    return names.empty() ? std::string("\xE2\x80\x94") /* em dash */ : join(names, "|");
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
    ::tc8::SomeIpCaptured c{};
    ::tc8::fillSomeIpCapturedFromFrame(c, f);

    std::vector<std::string> parts;
    std::size_t ipv4_eps = 0;
    for (std::size_t i = 0; i < c.sd_option_count; ++i) {
        if (c.sd_options[i].type == ::tc8::sd_option_type::kIpv4Endpoint) ++ipv4_eps;
    }

    const std::size_t shown = std::min<std::size_t>(c.sd_entry_count, 3);
    for (std::size_t i = 0; i < shown; ++i) {
        const auto &e = c.sd_entries[i];
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
    if (c.sd_entry_count > 3) {
        parts.push_back("+" + std::to_string(c.sd_entry_count - 3) + " more");
    }
    if (ipv4_eps != 0) {
        parts.push_back("ipv4_endpoints=" + std::to_string(ipv4_eps));
    }
    return parts.empty() ? std::string("SOME/IP-SD (no entries)") : ("SD " + join(parts, " | "));
}

// UT request/response carried in a kPort UDP datagram (mirror _dissect_ut).
std::string utSummary(const std::uint8_t *payload, std::uint32_t len) {
    if (len < 2) return "UT (truncated)";
    const std::uint8_t opcode_byte = payload[0];
    const std::uint8_t req_id = payload[1];
    const bool is_response = (opcode_byte & ::tc8::ut::kResponseBit) != 0;
    const std::uint8_t request_opcode = opcode_byte & 0x7Fu;
    const std::string name = utOpcodeName(request_opcode);

    if (!is_response) {
        return "UT req " + name + " (id=" + std::to_string(req_id) + ")";
    }
    if (len < 3) {
        return "UT resp " + name + " (truncated)";
    }
    const std::uint8_t status = payload[2];
    const std::uint8_t *body = payload + 3;
    const std::uint32_t blen = len - 3;
    std::vector<std::string> bits;
    switch (request_opcode) {
        case ::tc8::ut::OpGetReceivedUdp:
            if (blen >= 1) {
                const std::uint8_t received = body[0];
                bits.push_back("received=" + std::to_string(received));
                if (received == 1 && blen >= 9) {
                    const std::string sip = ipv4FromBe(be32(body + 1));
                    const std::uint16_t sport = be16(body + 5);
                    const std::uint16_t plen = be16(body + 7);
                    bits.push_back("src=" + sip + ":" + std::to_string(sport));
                    bits.push_back("len=" + std::to_string(plen));
                }
            }
            break;
        case ::tc8::ut::OpQueryTcpEstablished:
            if (blen >= 1) bits.push_back("established=" + std::to_string(body[0]));
            break;
        case ::tc8::ut::OpReceiveTcpData:
        case ::tc8::ut::OpReceiveTcpDataOob:
            if (blen >= 2) bits.push_back("recv_len=" + std::to_string(be16(body)));
            break;
        case ::tc8::ut::OpQueryLLAddress:
            if (blen >= 4) bits.push_back("addr=" + ipv4FromBe(be32(body)));
            break;
        case ::tc8::ut::OpQueryDhcpLease:
            if (blen >= 4) bits.push_back("lease=" + ipv4FromBe(be32(body)));
            break;
        case ::tc8::ut::OpQueryTcpInfo:
            if (blen >= 10) {
                bits.push_back("state=" + std::to_string(body[0]));
                bits.push_back("rto=" + std::to_string(be32(body + 1)) + "us");
                bits.push_back("retx=" + std::to_string(body[5]));
                bits.push_back("unacked=" + std::to_string(be32(body + 6)));
            }
            break;
        case ::tc8::ut::OpCreateUdpReceivePorts:
            if (blen >= 1) bits.push_back("actual=" + std::to_string(body[0]));
            break;
        default:
            break;
    }
    const std::string status_name = utStatusName(status);
    const std::string trailer = bits.empty() ? std::string() : (" " + join(bits, " "));
    return "UT resp " + name + " " + status_name + trailer;
}

bool someipIsSd(const ::tc8::SomeIpFrame &f) {
    // service_id 0xFFFF + method_id 0x8100 is the SD magic; the harness uses
    // these raw bytes throughout (someip_captured.h), so there is no named
    // constant to reference. The type/code parts route through the SSOT enums.
    return f.service_id == 0xFFFF && f.method_id == 0x8100 &&
           static_cast<::tc8::someip::MessageType>(f.message_type) ==
               ::tc8::someip::MessageType::NOTIFICATION &&
           static_cast<::tc8::someip::ReturnCode>(f.return_code) ==
               ::tc8::someip::ReturnCode::E_OK;
}

// ---------------------------------------------------------------------------
// Per-frame record assembled from the pipeline's variant events for one frame.
// ---------------------------------------------------------------------------

struct PacketRec {
    int idx = 0;
    long long ts_us = 0;
    long long ts_delta_us = 0;
    std::string src_mac;  // empty => emitted as null
    std::string dst_mac;
    std::optional<std::uint32_t> src_ip;  // captured-uint32 (octet0 in low byte)
    std::optional<std::uint32_t> dst_ip;
    std::string protocol = "UNKNOWN";
    std::string summary;
    std::string direction = "other";
};

// One decoded-protocol view of a frame. The pipeline emits a variant per layer
// (Ipv4Frame + UdpFrame + SomeIpFrame, etc.); the candidate with the highest
// `prio` is the deepest / most specific and wins the row.
struct Candidate {
    int prio = 0;
    std::string protocol;
    std::string summary;
    std::optional<std::uint32_t> src_ip;
    std::optional<std::uint32_t> dst_ip;
};

// Build a candidate from one pipeline event. IMPORTANT: this MUST run inside
// the pipeline listener, while the event's non-owning `payload_data` still
// points at the live libtins frame buffer (it dangles once processFrame
// returns). UT is presentation-decoded from the UDP payload here because the
// pipeline (verdict path) has no UT decoder.
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

// Fill protocol/summary/endpoints from the deepest candidate, or the
// raw-ethernet fallback when the pipeline emitted nothing (non-IP/non-ARP
// ethertype such as IPv6, or a frame too short/malformed to parse).
void chooseCandidate(PacketRec &r, const std::vector<Candidate> &cands,
                     std::uint16_t ethertype, std::uint32_t caplen) {
    const Candidate *best = nullptr;
    for (const auto &cand : cands) {
        if (best == nullptr || cand.prio > best->prio) best = &cand;
    }
    if (best != nullptr) {
        r.protocol = best->protocol;
        r.summary = best->summary;
        r.src_ip = best->src_ip;
        r.dst_ip = best->dst_ip;
        return;
    }
    if (caplen < 14u) {
        // Too short to carry an Ethernet header (ethertype was never read).
        // Leave the UNKNOWN / "" defaults rather than synthesize "ETH 0x0000".
        return;
    }
    if (ethertype == 0x0806) {
        r.protocol = "ARP";
        r.summary = "truncated ARP";
    } else if (ethertype == 0x0800) {
        r.protocol = "IPv4";
        r.summary = "truncated";
    } else {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "ETH 0x%04x", ethertype);
        r.protocol = buf;
        r.summary = std::to_string(caplen) + " B";
    }
}

// ---------------------------------------------------------------------------
// Direction + endpoint auto-detection (mirror decode_pcap.py).
// ---------------------------------------------------------------------------

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string directionOf(const std::string &src_mac, const std::string &dst_mac,
                        const std::string &tester_mac, const std::string &dut_mac) {
    const std::string s = toLower(src_mac);
    const std::string d = toLower(dst_mac);
    const std::string t = toLower(tester_mac);
    const std::string dm = toLower(dut_mac);
    if (!t.empty() && s == t) return "tester_to_dut";
    if (!dm.empty() && s == dm) return "dut_to_tester";
    if (!t.empty() && d == t) return "dut_to_tester";
    if (!dm.empty() && d == dm) return "tester_to_dut";
    return "other";
}

struct Endpoints {
    std::string tester_mac, dut_mac, tester_ip, dut_ip;
};

// Infer (tester, dut) from the capture: the two most frequent unicast src MACs
// are the endpoints; the one that emits first is the tester. IPs are the first
// src_ip seen sourced from each detected MAC.
Endpoints autodetect(const std::vector<PacketRec> &recs) {
    struct Acc {
        int count = 0;
        int first_seen = 0;
        int insert_order = 0;
        std::string ip;
    };
    std::unordered_map<std::string, Acc> by_mac;
    int order = 0;
    for (const auto &r : recs) {
        const std::string mac = toLower(r.src_mac);
        if (mac.empty() || mac == "00:00:00:00:00:00") continue;
        unsigned first_byte = 0;
        if (std::sscanf(mac.c_str(), "%2x", &first_byte) != 1) continue;
        if ((first_byte & 0x01u) != 0) continue;  // multicast / broadcast bit
        auto it = by_mac.find(mac);
        if (it == by_mac.end()) {
            Acc a;
            a.first_seen = r.idx;
            a.insert_order = order++;
            if (r.src_ip.has_value()) a.ip = ipv4ToDotted(*r.src_ip);
            by_mac.emplace(mac, a);
            it = by_mac.find(mac);
        } else if (it->second.ip.empty() && r.src_ip.has_value()) {
            it->second.ip = ipv4ToDotted(*r.src_ip);
        }
        it->second.count++;
    }
    if (by_mac.empty()) return {};

    std::vector<std::pair<std::string, Acc>> ranked(by_mac.begin(), by_mac.end());
    std::sort(ranked.begin(), ranked.end(), [](const auto &a, const auto &b) {
        if (a.second.count != b.second.count) return a.second.count > b.second.count;
        return a.second.insert_order < b.second.insert_order;
    });

    Endpoints ep;
    if (ranked.size() == 1) {
        ep.tester_mac = ranked[0].first;
        ep.tester_ip = ranked[0].second.ip;
        return ep;
    }
    const auto &a = ranked[0];
    const auto &b = ranked[1];
    const bool a_first = a.second.first_seen <= b.second.first_seen;
    const auto &tester = a_first ? a : b;
    const auto &dut = a_first ? b : a;
    ep.tester_mac = tester.first;
    ep.tester_ip = tester.second.ip;
    ep.dut_mac = dut.first;
    ep.dut_ip = dut.second.ip;
    return ep;
}

long long absTsUs(const pcap_pkthdr &hdr, int precision) {
    const long long subsec = precision == PCAP_TSTAMP_PRECISION_NANO
                                 ? static_cast<long long>(hdr.ts.tv_usec) / 1000LL
                                 : static_cast<long long>(hdr.ts.tv_usec);
    return static_cast<long long>(hdr.ts.tv_sec) * 1'000'000LL + subsec;
}

}  // namespace

DecodePcapCommand::DecodePcapCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "decode-pcap",
        "Decode a saved pcap into the documentation site's PacketCapture JSON "
        "(replaces site/scripts/decode_pcap.py; see docs/tech-debt.md TD-05)");
    sub_->add_option("case_id", case_id_, "Case ID (uppercased into the output)")->required();
    sub_->add_option("outcome", outcome_, "Run outcome")
        ->required()
        ->check(CLI::IsMember({"pass", "fail"}));
    sub_->add_option("pcap_file", pcap_file_, "Path to the saved .pcap")
        ->required()
        ->check(CLI::ExistingFile);
    sub_->add_option("--out", out_path_, "Output JSON path")->required();
    sub_->add_option("--captured-at", captured_at_, "ISO-8601 capture timestamp (display only)");
    sub_->add_option("--trace-json", trace_json_path_,
                     "Harness transition-trace sidecar (<pcap>.trace.json). Merged "
                     "verbatim under \"captured_trace\"; absent path is ignored.");
    sub_->add_option("--tester-mac", tester_mac_, "Tester MAC (default: auto-detect)");
    sub_->add_option("--tester-ip", tester_ip_, "Tester IPv4 (default: auto-detect)");
    sub_->add_option("--dut-mac", dut_mac_, "DUT MAC (default: auto-detect)");
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 (default: auto-detect)");
}

int DecodePcapCommand::run() {
    auto src = capture::PcapSource::openOffline(pcap_file_);
    const int dlt = src->datalink();
    const int precision = src->tstampPrecision();

    // The listener builds each event's presentation candidate eagerly, while
    // the event's non-owning payload pointer is still valid (it dangles once
    // processFrame returns). chooseCandidate then picks the deepest per frame.
    std::vector<Candidate> frame_cands;
    dissect::PacketPipeline pipeline(
        [&frame_cands](const ::tc8::CapturedEvent &ev) { frame_cands.push_back(makeCandidate(ev)); });
    pipeline.setTstampPrecision(precision);

    std::vector<PacketRec> recs;
    long long first_ts = -1;
    long long prev_ts = -1;
    int idx = 0;

    while (true) {
        const int n = src->dispatch(
            /*max_frames=*/-1, [&](const pcap_pkthdr &hdr, const u_char *data) {
                const long long ts = absTsUs(hdr, precision);
                if (first_ts < 0) {
                    first_ts = ts;
                    prev_ts = ts;
                }
                PacketRec r;
                r.idx = idx;
                r.ts_us = ts - first_ts;
                r.ts_delta_us = idx > 0 ? (ts - prev_ts) : 0;

                std::uint16_t ethertype = 0;
                if (hdr.caplen >= 14u) {
                    r.dst_mac = macToHex(data);
                    r.src_mac = macToHex(data + 6);
                    ethertype = static_cast<std::uint16_t>(
                        (static_cast<unsigned>(data[12]) << 8) | data[13]);
                }

                frame_cands.clear();
                pipeline.processFrame(hdr, data, dlt);
                chooseCandidate(r, frame_cands, ethertype, hdr.caplen);

                recs.push_back(std::move(r));
                prev_ts = ts;
                ++idx;
            });
        if (n < 0) {
            if (n == -2) break;  // pcap_breakloop
            std::fprintf(stderr, "dispatch error: %s\n", src->lastError());
            return 1;
        }
        if (n == 0 && src->isOffline()) break;  // end of pcap
    }

    // Endpoint identities: CLI override else auto-detect from the capture.
    const Endpoints det = autodetect(recs);
    const std::string tester_mac = tester_mac_.empty() ? det.tester_mac : tester_mac_;
    const std::string dut_mac    = dut_mac_.empty()    ? det.dut_mac    : dut_mac_;
    const std::string tester_ip  = tester_ip_.empty()  ? det.tester_ip  : tester_ip_;
    const std::string dut_ip     = dut_ip_.empty()     ? det.dut_ip     : dut_ip_;

    for (auto &r : recs) {
        r.direction = directionOf(r.src_mac, r.dst_mac, tester_mac, dut_mac);
    }

    std::string case_id_upper = case_id_;
    std::transform(case_id_upper.begin(), case_id_upper.end(), case_id_upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    // Build the PacketCapture JSON (one packet object per line for readable
    // git diffs on the committed pcap-data branch).
    std::string out;
    out.reserve(recs.size() * 160 + 512);
    out.append("{\n");
    out.append("  \"case_id\": ");      appendJsonString(out, case_id_upper);   out.append(",\n");
    out.append("  \"outcome\": ");      appendJsonString(out, outcome_);        out.append(",\n");
    out.append("  \"captured_at\": ");  appendJsonString(out, captured_at_);    out.append(",\n");
    auto emitTop = [&](const char *key, const std::string &v) {
        out.append("  \"");
        out.append(key);
        out.append("\": ");
        if (v.empty()) {
            out.append("null");
        } else {
            appendJsonString(out, v);
        }
        out.append(",\n");
    };
    emitTop("tester_mac", tester_mac);
    emitTop("tester_ip", tester_ip);
    emitTop("dut_mac", dut_mac);
    emitTop("dut_ip", dut_ip);

    out.append("  \"packets\": [");
    for (std::size_t i = 0; i < recs.size(); ++i) {
        const auto &r = recs[i];
        out.append(i == 0 ? "\n    {" : ",\n    {");
        out.append("\"idx\": ");           out.append(std::to_string(r.idx));
        out.append(", \"ts_us\": ");       out.append(std::to_string(r.ts_us));
        out.append(", \"ts_delta_us\": "); out.append(std::to_string(r.ts_delta_us));
        out.append(", \"direction\": ");   appendJsonString(out, r.direction);
        out.append(", \"src_mac\": ");
        if (r.src_mac.empty()) out.append("null"); else appendJsonString(out, r.src_mac);
        out.append(", \"dst_mac\": ");
        if (r.dst_mac.empty()) out.append("null"); else appendJsonString(out, r.dst_mac);
        out.append(", \"src_ip\": ");
        if (r.src_ip.has_value()) appendJsonString(out, ipv4ToDotted(*r.src_ip)); else out.append("null");
        out.append(", \"dst_ip\": ");
        if (r.dst_ip.has_value()) appendJsonString(out, ipv4ToDotted(*r.dst_ip)); else out.append("null");
        out.append(", \"protocol\": ");    appendJsonString(out, r.protocol);
        out.append(", \"summary\": ");     appendJsonString(out, r.summary);
        out.append("}");
    }
    out.append(recs.empty() ? "]" : "\n  ]");

    // Evidence Export: merge the harness transition trace verbatim. The harness
    // writes well-formed JSON (test_runner.h::dumpTraceJson); a missing/empty
    // sidecar is silently skipped (the site walker then has no trace block).
    if (!trace_json_path_.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(trace_json_path_, ec)) {
            if (FILE *fp = std::fopen(trace_json_path_.c_str(), "rb")) {
                std::string trace;
                char chunk[4096];
                std::size_t got = 0;
                while ((got = std::fread(chunk, 1, sizeof(chunk), fp)) > 0) {
                    trace.append(chunk, got);
                }
                std::fclose(fp);
                // Trim trailing whitespace/newline so the embedded value is tidy.
                while (!trace.empty() && (trace.back() == '\n' || trace.back() == '\r' ||
                                          trace.back() == ' ' || trace.back() == '\t')) {
                    trace.pop_back();
                }
                if (isWellFormedJsonObject(trace)) {
                    out.append(",\n  \"captured_trace\": ");
                    out.append(trace);
                } else if (!trace.empty()) {
                    std::fprintf(stderr,
                                 "warning: trace sidecar '%s' is not well-formed "
                                 "JSON; omitting captured_trace\n",
                                 trace_json_path_.c_str());
                }
            }
        }
    }

    out.append("\n}\n");

    const std::filesystem::path out_path(out_path_);
    if (out_path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);
    }
    FILE *fp = std::fopen(out_path_.c_str(), "wb");
    if (fp == nullptr) {
        std::fprintf(stderr, "error: cannot open output '%s'\n", out_path_.c_str());
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), fp);
    std::fclose(fp);
    std::printf("wrote %zu packet(s) to %s\n", recs.size(), out_path_.c_str());
    return 0;
}

}  // namespace tc8::cli
