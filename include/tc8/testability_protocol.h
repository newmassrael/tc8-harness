#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// AUTOSAR Testability Protocol and Service Primitives wire framing — the
// single source of truth shared by the tester-side client
// (src/stimulus/testability_client.*) and the DUT-side endpoint
// (dut/dut_service/testability_server.*).
//
// Spec: docs/spec/AUTOSAR_PRS_TestabilityProtocolAndServicePrimitives.pdf,
// AUTOSAR TC Release 1.2.0, Document ID 778, PRS_TPSP §6 "Protocol Specification".
//
// The TC8 Upper Tester (see upper_tester_protocol.h) is spec-defined only as "a separate UDP
// communication that triggers wished behaviors on the IUT"; the concrete
// wire format is left open and the spec points at this AUTOSAR Testability
// Protocol "as an example". The in-house opcode UT (tc8::ut,
// include/tc8/upper_tester_protocol.h, port 30600) is one realisation; this
// header is the standard realisation, enabling the harness to drive a
// standard-compliant third-party / OEM DUT.
//
// ## Message format (PRS_TPSP §6.1)
//
// A testability message IS a SOME/IP message (the format "is derived from the
// SOME/IP standard"), big-endian on the wire (PRS_TPSP §6.7), with two header fields
// reinterpreted:
//
//   SOME/IP 16-byte header           Testability meaning (PRS_TPSP §6.1 figure, p.10)
//   ------------------------------   ---------------------------------------
//   Message ID  bits  0..15          SID  — Service ID (default 0x0105, cfg)
//   Message ID  bit   16             EVB  — Event Bit (set on event messages)
//   Message ID  bits  17..23         GID  — Service Group ID (7 bits, PRS_TPSP §6.9)
//   Message ID  bits  24..31         PID  — Service Primitive ID (8 bits, PRS_TPSP §6.10)
//   Length [32]                      LEN  — 8 + parameter bytes
//   Request ID (Client/Session) [32] d.c. — "must be ignored"
//   Protocol Version [8]             0x01 (constant)
//   Interface Version [8]            0x01 (constant)
//   Message Type [8]                 TID  — Request 0x00 / Response 0x80 / Event 0x02 (PRS_TPSP §6.2)
//   Return Code [8]                  RID  — Result ID (PRS_TPSP §6.8)
//   Payload [variable]               DAT  — Parameter Data (PRS_TPSP §6.7)
//
// The SOME/IP Method ID half therefore encodes (EVB<<15)|(GID<<8)|PID — see
// methodId() / gidOf() / pidOf() / isEvent() below, the only place that
// decomposition lives.

namespace tc8::testability {

// PRS_TPSP §6.1: Testability Service ID, default 0x0105, configurable per deployment.
inline constexpr std::uint16_t kDefaultServiceId = 0x0105;

// Harness-convention UDP port the testability service listens on. The spec
// (PRS_TPSP §5.1) only fixes "on top of UDP or TCP" — the port is deployment config.
// Chosen disjoint from the opcode UT (tc8::ut::kPort 30600), the SOME/IP
// unicast range (30490..30510) and vsomeip defaults so pcap readers and BPF
// filters attribute frames unambiguously. Overridable per-DUT via
// TestabilityConfig.
inline constexpr std::uint16_t kDefaultPort = 30700;

// PRS_TPSP §6.1: Protocol Version and Interface Version are constant for all messages.
inline constexpr std::uint8_t kProtocolVersion = 0x01;
inline constexpr std::uint8_t kInterfaceVersion = 0x01;

// PRS_TPSP §6.2: Message Type ID (TID) — carried in the SOME/IP message_type byte.
inline constexpr std::uint8_t kTidRequest = 0x00;
inline constexpr std::uint8_t kTidResponse = 0x80;
inline constexpr std::uint8_t kTidEvent = 0x02;

// PRS_TPSP §6.1: Event Bit (EVB) — bit 15 of the 16-bit Method ID half (bit 16 of the
// 32-bit Message ID). Set on event messages, clear on request/response.
inline constexpr std::uint16_t kEventBit = 0x8000;

// PRS_TPSP §6.9: Service Group IDs (GID), a 7-bit field. Standard groups; non-standard
// extensions count backwards from 0x7F (PRS_TPSP §6.6).
enum Gid : std::uint8_t {
    kGidGeneral = 0x00,
    kGidUdp = 0x01,
    kGidTcp = 0x02,
    kGidIcmp = 0x03,
    kGidIcmpv6 = 0x04,
    kGidIp = 0x05,
    kGidIpv6 = 0x06,
    kGidDhcp = 0x07,
    kGidDhcpv6 = 0x08,
    kGidArp = 0x09,
    kGidNdp = 0x0A,
    kGidEth = 0x0B,
    kGidPhy = 0x0C,
};

// PRS_TPSP §6.10 GENERAL group (GID 0x00) Service Primitive IDs (PID) — all mandatory.
inline constexpr std::uint8_t kPidGetVersion = 0x01;  // resp: major/minor/patch (uint16 x3)
inline constexpr std::uint8_t kPidStartTest = 0x02;   // no request parameters
inline constexpr std::uint8_t kPidEndTest = 0x03;     // req: tcId(uint16) + tsName(text)

// PRS_TPSP §6.9 UDP group (0x01) / TCP group (0x02) shared Service Primitive IDs. The
// same PID denotes the per-group primitive (parameter sets differ by GID).
inline constexpr std::uint8_t kPidCloseSocket = 0x00;
inline constexpr std::uint8_t kPidCreateAndBind = 0x01;
inline constexpr std::uint8_t kPidSendData = 0x02;
inline constexpr std::uint8_t kPidReceiveAndForward = 0x03;
inline constexpr std::uint8_t kPidListenAndAccept = 0x04;  // TCP only
inline constexpr std::uint8_t kPidConnect = 0x05;          // TCP only
inline constexpr std::uint8_t kPidConfigureSocket = 0x06;
inline constexpr std::uint8_t kPidShutdown = 0x07;

// PRS_TPSP §6.10 ICMP group (0x03) / ICMPv6 group (0x04) Service Primitive ID.
// PID values are scoped per GID (PRS_TPSP §6.10: separate primitives reuse "the
// same service identifier (PID) but a different GID and set of parameters"), so
// ECHO_REQUEST reuses the 0x00 slot that denotes CLOSE_SOCKET in the UDP/TCP
// groups — the GID disambiguates which primitive a 0x00 PID names.
inline constexpr std::uint8_t kPidEchoRequest = 0x00;

// PRS_TPSP §6.10 ETH group (0x0B) Service Primitive IDs. INTERFACE_UP/DOWN each
// take a single ifName(text) and report E_IIF on an unknown interface. These
// 0x00/0x01 PIDs are GID-scoped (they name CLOSE_SOCKET/CREATE_AND_BIND in the
// UDP/TCP groups) — the GID disambiguates which primitive a PID names.
inline constexpr std::uint8_t kPidInterfaceUp = 0x00;
inline constexpr std::uint8_t kPidInterfaceDown = 0x01;

// PRS_TPSP §6.10 IP group (0x05) / IPv6 group (0x06) Service Primitive IDs.
// STATIC_ADDRESS assigns an addr(ipxaddr) + CIDR netMask(uint8) to ifName(text);
// STATIC_ROUTE adds a subNet(ipxaddr)/netMask(uint8)-via-gateway(ipxaddr) route
// for ifName(text) without affecting persistent configuration. Both report E_IIF
// on an unknown interface. These GID-scoped 0x00/0x01 PIDs name CLOSE_SOCKET /
// CREATE_AND_BIND in the UDP/TCP groups — the GID disambiguates which a PID names.
inline constexpr std::uint8_t kPidStaticAddress = 0x00;
inline constexpr std::uint8_t kPidStaticRoute = 0x01;

// PRS_TPSP §6.10 SHUTDOWN typeId — selects which transfer direction the
// primitive disallows on the socket (maps to the BSD shutdown(2) `how`).
inline constexpr std::uint8_t kShutdownRd = 0x00;    // further reception disallowed (SHUT_RD)
inline constexpr std::uint8_t kShutdownWr = 0x01;    // further transmission disallowed (SHUT_WR)
inline constexpr std::uint8_t kShutdownRdWr = 0x02;  // transmission and reception (SHUT_RDWR)

// PRS_TPSP §6.10.10 CONFIGURE_SOCKET paramId selectors (UDP/TCP). Each fixes the
// paramVal byte length shown; the IP-level options apply to both groups, MSS and
// Nagle are TCP-only and the checksum toggle UDP-only. Non-standard parameters
// count down from 0xFFFF (PRS_TPSP §6.10.10).
inline constexpr std::uint16_t kCfgTtl = 0x0000;               // 1B: TTL / Hop Limit
inline constexpr std::uint16_t kCfgPriority = 0x0001;          // 1B: traffic class / DSCP & ECN
inline constexpr std::uint16_t kCfgDontFragment = 0x0002;      // 1B: IP DF (Don't Fragment)
inline constexpr std::uint16_t kCfgIpTimestampOption = 0x0003; // N B: IP Timestamp option-4 bytes
inline constexpr std::uint16_t kCfgTos = 0x0004;               // 1B: IP Type of Service (RFC 791)
inline constexpr std::uint16_t kCfgMss = 0x0005;               // 2B: TCP MSS 500..1460 (TCP only)
inline constexpr std::uint16_t kCfgNagle = 0x0006;             // 1B: Nagle enable=1 (TCP only)
inline constexpr std::uint16_t kCfgUdpChecksum = 0x0007;       // 1B: UDP checksum tx enable=1 (UDP)

// PRS_TPSP §6.8 Result IDs (RID) — carried in the SOME/IP return_code byte.
inline constexpr std::uint8_t kRidEOk = 0x00;   // performed successfully
inline constexpr std::uint8_t kRidENok = 0x01;  // general error
// 0x02..0x7F: AUTOSAR-specific error codes (API returns other than E_OK/E_NOK).
// Testability-specific (PRS_TPSP §6.8):
inline constexpr std::uint8_t kRidENtf = 0xFF;  // service primitive not found
inline constexpr std::uint8_t kRidEPen = 0xFE;  // Upper Tester / SP pending
inline constexpr std::uint8_t kRidEIsb = 0xFD;  // insufficient buffer size
inline constexpr std::uint8_t kRidEInv = 0xFC;  // invalid input or parameter
// Service-primitive-specific (PRS_TPSP §6.8):
inline constexpr std::uint8_t kRidEIsd = 0xEF;  // invalid socket ID
inline constexpr std::uint8_t kRidEUcs = 0xEE;  // unable to create / no free socket
inline constexpr std::uint8_t kRidEUbs = 0xED;  // unable to bind, port taken
inline constexpr std::uint8_t kRidEIif = 0xEC;  // invalid network / virtual interface

// PRS_TPSP §6.10 GET_VERSION response — bound to the TC release the protocol is based
// on. This build implements TC 1.2.0.
inline constexpr std::uint16_t kVersionMajor = 1;
inline constexpr std::uint16_t kVersionMinor = 2;
inline constexpr std::uint16_t kVersionPatch = 0;

// ── PRS_TPSP §6.1 Method ID composition — the sole place GID/PID/EVB pack/unpack ──

// Compose the SOME/IP Method ID half from a group + primitive (EVB clear for
// request/response). GID is masked to its 7-bit field.
inline constexpr std::uint16_t methodId(std::uint8_t gid, std::uint8_t pid,
                                        bool event = false) {
    // Compose in unsigned so the bitwise OR never mixes signed/unsigned operands
    // (an int promotion of `<< 8` would otherwise trip -Wsign-conversion at -O0).
    const unsigned evb = event ? static_cast<unsigned>(kEventBit) : 0u;
    const unsigned grp = static_cast<unsigned>(gid & 0x7Fu) << 8;
    const unsigned prm = static_cast<unsigned>(pid);
    return static_cast<std::uint16_t>(evb | grp | prm);
}

inline constexpr std::uint8_t gidOf(std::uint16_t method_id) {
    return static_cast<std::uint8_t>((method_id >> 8) & 0x7Fu);
}

inline constexpr std::uint8_t pidOf(std::uint16_t method_id) {
    return static_cast<std::uint8_t>(method_id & 0xFFu);
}

inline constexpr bool isEvent(std::uint16_t method_id) {
    return (method_id & kEventBit) != 0u;
}

// ── Header-only 16-byte SOME/IP codec ──
//
// Shared by the tester client, the DUT endpoint, and the unit test so all
// three agree on the byte layout by construction (the testability-specific
// reinterpretation above is the only changeable part, and it lives here once).
// Big-endian per PRS_TPSP §6.7. The DUT firmware uses this directly; the harness client
// builds with stimulus::buildMethodRequest (the existing SOME/IP builder) and
// the unit test cross-checks that builder's output against parseHeader here.

inline constexpr std::size_t kHeaderSize = 16;

// Decoded testability header. service_id / method_id / tid / rid carry the
// reinterpreted SOME/IP fields; client/session ids are don't-care. `length`
// is a parse OUTPUT (the wire LEN field); buildMessage ignores it and always
// emits 8 + DAT per PRS_TPSP §6.1.
struct Header {
    std::uint16_t service_id = kDefaultServiceId;
    std::uint16_t method_id = 0;  // (EVB<<15)|(GID<<8)|PID
    std::uint32_t length = 8;     // parse output: wire LEN = 8 + DAT bytes
    std::uint16_t client_id = 0;  // d.c.
    std::uint16_t session_id = 0; // d.c.
    std::uint8_t protocol_version = kProtocolVersion;
    std::uint8_t interface_version = kInterfaceVersion;
    std::uint8_t tid = kTidRequest;  // message_type
    std::uint8_t rid = kRidEOk;      // return_code
};

namespace detail {
inline void putBe16(std::vector<std::uint8_t> &out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
inline void putBe32(std::vector<std::uint8_t> &out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
inline std::uint16_t getBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
inline std::uint32_t getBe32(const std::uint8_t *p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}
}  // namespace detail

// Serialise a full testability message (16-byte header + DAT) to a byte
// vector. The LEN field is always 8 + dat_len per PRS_TPSP §6.1 (h.length is a parse
// output and is ignored here).
inline std::vector<std::uint8_t> buildMessage(Header h, const std::uint8_t *dat = nullptr,
                                              std::size_t dat_len = 0) {
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + dat_len);
    detail::putBe16(out, h.service_id);
    detail::putBe16(out, h.method_id);
    detail::putBe32(out, static_cast<std::uint32_t>(8u + dat_len));
    detail::putBe16(out, h.client_id);
    detail::putBe16(out, h.session_id);
    out.push_back(h.protocol_version);
    out.push_back(h.interface_version);
    out.push_back(h.tid);
    out.push_back(h.rid);
    if (dat != nullptr && dat_len > 0) {
        out.insert(out.end(), dat, dat + dat_len);
    }
    return out;
}

// Parse the 16-byte header from `data`. Returns nullopt when fewer than 16
// bytes are available. Does not validate `length` against `len` — the caller
// decides whether a truncated payload is fatal. DAT begins at data + 16.
inline std::optional<Header> parseHeader(const std::uint8_t *data, std::size_t len) {
    if (data == nullptr || len < kHeaderSize) {
        return std::nullopt;
    }
    Header h;
    h.service_id = detail::getBe16(data + 0);
    h.method_id = detail::getBe16(data + 2);
    h.length = detail::getBe32(data + 4);
    h.client_id = detail::getBe16(data + 8);
    h.session_id = detail::getBe16(data + 10);
    h.protocol_version = data[12];
    h.interface_version = data[13];
    h.tid = data[14];
    h.rid = data[15];
    return h;
}

// ── PRS_TPSP §6.7 parameter serialisation (DAT build/parse) ──
//
// The testability data types (PRS_TPSP §6.7) — big-endian scalars, vint8 (uint16 n +
// n bytes), ipxaddr (vint8 n=4/16), text (vint8 of BOM + UTF-8 + null) — are
// testability-spec-specific encodings, so they live with the protocol SSOT and
// are shared verbatim by the tester client, the probe, and the DUT endpoint
// (the two ends of every primitive must agree on this encoding).

inline void appendU16(std::vector<std::uint8_t> &dat, std::uint16_t v) {
    detail::putBe16(dat, v);
}

// PRS_TPSP §6.7 vint8: uint16 length prefix followed by the n bytes.
inline void appendVint8(std::vector<std::uint8_t> &dat, const std::uint8_t *p,
                        std::size_t n) {
    detail::putBe16(dat, static_cast<std::uint16_t>(n));
    if (p != nullptr && n > 0) {
        dat.insert(dat.end(), p, p + n);
    }
}

// PRS_TPSP §6.7.5.1 ipxaddr (IPv4): vint8 with n=4 carrying the address in wire order.
// `ip_be` is the sockaddr_in::s_addr value (network byte order).
inline void appendIpv4Addr(std::vector<std::uint8_t> &dat, std::uint32_t ip_be) {
    const auto *b = reinterpret_cast<const std::uint8_t *>(&ip_be);
    appendVint8(dat, b, 4);
}

// PRS_TPSP §6.7.5.1 ipxaddr (IPv6): vint8 with n=16 carrying the address in wire
// order (the in6_addr / sin6_addr bytes).
inline void appendIpv6Addr(std::vector<std::uint8_t> &dat, const std::uint8_t addr16[16]) {
    appendVint8(dat, addr16, 16);
}

// PRS_TPSP §6.7.5.2 text: vint8 of [BOM(EF BB BF) + UTF-8 bytes + null]; empty => n=0
// (per the spec's `n = 0 | 4..65535` rule).
inline void appendText(std::vector<std::uint8_t> &dat, const std::string &text) {
    if (text.empty()) {
        detail::putBe16(dat, 0);
        return;
    }
    static constexpr std::uint8_t kBom[3] = {0xEF, 0xBB, 0xBF};
    const std::size_t n = sizeof(kBom) + text.size() + 1u;  // + null terminator
    detail::putBe16(dat, static_cast<std::uint16_t>(n));
    dat.insert(dat.end(), kBom, kBom + sizeof(kBom));
    dat.insert(dat.end(), text.begin(), text.end());
    dat.push_back(0x00);
}

inline std::uint16_t readU16(const std::uint8_t *p) {
    return detail::getBe16(p);
}

// Parse a PRS_TPSP §6.7 vint8 at dat[off]: advance `off` past the field and point
// `body`/`body_len` at the n bytes. False if the field runs past dat_len.
inline bool readVint8(const std::uint8_t *dat, std::size_t dat_len, std::size_t &off,
                      const std::uint8_t *&body, std::uint16_t &body_len) {
    if (off + 2 > dat_len) {
        return false;
    }
    const std::uint16_t n = detail::getBe16(dat + off);
    off += 2;
    if (off + static_cast<std::size_t>(n) > dat_len) {
        return false;
    }
    body = dat + off;
    body_len = n;
    off += n;
    return true;
}

// Decode a PRS_TPSP §6.7.5.2 text field at dat[off] into `out` — the inverse of
// appendText. The wire body is a vint8 of [BOM(EF BB BF) + UTF-8 + null]; this
// strips a leading BOM and a trailing null when present (tolerating a bare
// string a third-party client may send) and yields the UTF-8 content. An empty
// field (n=0) decodes to "". False only if the vint8 itself runs past dat_len.
inline bool readText(const std::uint8_t *dat, std::size_t dat_len, std::size_t &off,
                     std::string &out) {
    const std::uint8_t *body = nullptr;
    std::uint16_t body_len = 0;
    if (!readVint8(dat, dat_len, off, body, body_len)) {
        return false;
    }
    std::size_t start = 0;
    std::size_t end = body_len;
    if (body_len >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF) {
        start = 3;  // skip the UTF-8 BOM
    }
    if (end > start && body[end - 1] == 0x00) {
        end -= 1;  // drop the null terminator
    }
    out.assign(reinterpret_cast<const char *>(body + start), end - start);
    return true;
}

}  // namespace tc8::testability
