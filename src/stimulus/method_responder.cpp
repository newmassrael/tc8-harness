#include "stimulus/method_responder.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <optional>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "tc8/autosar/someiptp.h"             // kMessageTypeTpFlag / kSegmentHeaderLen / parseTpHeader (TP SSOT).
#include "someip/wire.h"                  // getBe16 / parseHeader / Header / MessageType.
#include "stimulus/iface_addr.h"          // ipv4FromWire.
#include "stimulus/someip_rpc_builder.h"  // emitMethodReply / MethodEndpoint.

namespace tc8::stimulus {

namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint8_t kIpProtoUdp = 17;

// Layer header lengths (the SOME/IP header size is someip::kHeaderSize). The
// smallest frame this can parse is Ethernet(14) + IPv4(20, no options) + UDP(8) +
// SOME/IP header(16) = 58 bytes; captured frames may carry trailing Ethernet
// padding to the 60-byte minimum, which the payload extraction below excludes via
// the UDP length field.
constexpr std::size_t kEthHdrLen = 14;
constexpr std::size_t kIpv4MinHdrLen = 20;
constexpr std::size_t kUdpHdrLen = 8;

// RX scratch for one frame. A non-TP SOME/IP Method Request over Ethernet fits in
// one MTU-sized datagram; 2048 covers that whole frame plus padding so it is read
// in one recvfrom and bounds-checked, never partially. A larger (TP-segmented or
// jumbo) Request is out of scope (the parser is non-TP, see the header) and would
// be recvfrom-truncated, then rejected by the bounds/length checks rather than
// mis-parsed.
constexpr std::size_t kRxBufLen = 2048;

// Eth+IPv4+UDP+SOME/IP-header parse shared by parseMethodRequest and
// parseFirstTpRequestSegment: validate the lower layers, match the UDP
// destination port + (service, method), and surface the SOME/IP header (raw
// message_type), the reply target, the SOME/IP header's frame offset, and the UDP
// Length field. Each caller applies its OWN message-type check + payload
// extraction, so the L2/L3/L4 walk lives in exactly one place. Returns false on
// any structural mismatch (leaving `out` unspecified).
struct UdpSomeIp {
    someip::Header h;
    std::uint32_t src_ip_be = 0;
    std::uint16_t src_port = 0;
    std::size_t someip_off = 0;   // frame offset of the SOME/IP header
    std::uint16_t udp_total = 0;  // UDP Length field (header + payload)
};

bool parseUdpSomeIp(const std::uint8_t *frame, std::size_t len, std::uint16_t service_id,
                    std::uint16_t method_id, std::uint16_t service_port, UdpSomeIp &out) {
    if (frame == nullptr || len < kEthHdrLen + kIpv4MinHdrLen + kUdpHdrLen + someip::kHeaderSize) {
        return false;
    }
    if (someip::getBe16(frame + 12) != kEtherTypeIpv4) {
        return false;
    }
    const std::uint8_t *ip = frame + kEthHdrLen;
    if ((ip[0] >> 4) != 4) {  // IPv4 version nibble
        return false;
    }
    // IHL (low nibble of byte 0) gives the IPv4 header length in 32-bit words;
    // IPv4 options push UDP further out, so the extent must be re-checked.
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
    if (ihl < kIpv4MinHdrLen || ip[9] != kIpProtoUdp) {
        return false;
    }
    if (len < kEthHdrLen + ihl + kUdpHdrLen + someip::kHeaderSize) {
        return false;
    }
    const std::uint8_t *udp = ip + ihl;
    if (someip::getBe16(udp + 2) != service_port) {  // UDP destination port
        return false;
    }
    // SOME/IP header via the wire SSOT (the inverse of appendHeader), so the field
    // offsets are not re-spelled here. The extent above guarantees kHeaderSize.
    const std::uint8_t *sip = udp + kUdpHdrLen;
    if (!someip::parseHeader(sip, len - static_cast<std::size_t>(sip - frame), out.h)) {
        return false;
    }
    if (out.h.service_id != service_id || out.h.method_id != method_id) {
        return false;
    }
    out.src_ip_be = ipv4FromWire(ip + 12);  // IPv4 source address @ +12
    out.src_port = someip::getBe16(udp + 0);
    out.someip_off = static_cast<std::size_t>(sip - frame);
    out.udp_total = someip::getBe16(udp + 4);
    return true;
}

// Args after `header_bytes` of on-wire header (16 for a plain message, 20 for a TP
// segment), bounded by the UDP Length field (so Ethernet padding on a sub-60-byte
// frame is excluded) and clamped to what is physically present (so a malformed
// over-long length cannot over-read). The SOME/IP Length field is NOT trusted.
std::vector<std::uint8_t> extractArgs(const std::uint8_t *frame, std::size_t len,
                                      std::size_t args_off, std::uint16_t udp_total,
                                      std::size_t header_bytes) {
    const std::size_t by_udp = (udp_total >= kUdpHdrLen + header_bytes)
                                   ? (udp_total - kUdpHdrLen - header_bytes)
                                   : 0;
    const std::size_t avail = (len > args_off) ? (len - args_off) : 0;
    const std::size_t args_len = std::min(avail, by_udp);
    return std::vector<std::uint8_t>(frame + args_off, frame + args_off + args_len);
}

}  // namespace

std::optional<MethodRequestObservation>
parseMethodRequest(const std::uint8_t *frame, std::size_t len, std::uint16_t service_id,
                   std::uint16_t method_id, std::uint16_t service_port) {
    UdpSomeIp p;
    if (!parseUdpSomeIp(frame, len, service_id, method_id, service_port, p)) {
        return std::nullopt;
    }
    // Only a Request (0x00) is answered; a RequestNoReturn (0x01) gets NO reply
    // per PRS_SOMEIP_00701, and Response/Error/Notification/TP are not ours.
    if (p.h.message_type != static_cast<std::uint8_t>(someip::MessageType::REQUEST)) {
        return std::nullopt;
    }
    MethodRequestObservation obs;
    obs.src_ip_be = p.src_ip_be;
    obs.src_port = p.src_port;
    obs.service_id = p.h.service_id;  // read from the frame, not echoed from the args
    obs.method_id = p.h.method_id;
    obs.client_id = p.h.client_id;
    obs.session_id = p.h.session_id;
    obs.payload = extractArgs(frame, len, p.someip_off + someip::kHeaderSize, p.udp_total,
                              someip::kHeaderSize);
    return obs;
}

std::optional<MethodRequestObservation>
parseFirstTpRequestSegment(const std::uint8_t *frame, std::size_t len, std::uint16_t service_id,
                           std::uint16_t method_id, std::uint16_t service_port) {
    UdpSomeIp p;
    if (!parseUdpSomeIp(frame, len, service_id, method_id, service_port, p)) {
        return std::nullopt;
    }
    // A TP Request segment carries the base REQUEST type with the TP flag set;
    // a plain Request (no flag), a later message type, or a non-TP frame is not a
    // first-segment trigger.
    constexpr std::uint8_t kTpRequest =
        static_cast<std::uint8_t>(someip::MessageType::REQUEST) | someiptp::kMessageTypeTpFlag;
    if (p.h.message_type != kTpRequest) {
        return std::nullopt;
    }
    // The 4-byte TP header follows the 16-byte SOME/IP header; require it present
    // and parse it via the TP wire SSOT. Only the FIRST segment (Offset 0) triggers
    // (later segments carry the same session but must not re-fire the responder).
    const std::size_t tp_off = p.someip_off + someip::kHeaderSize;
    if (len < tp_off + someiptp::kTpHeaderLen) {
        return std::nullopt;
    }
    someiptp::TpSegmentHeader tp;
    if (!someiptp::parseTpHeader(frame + tp_off, len - tp_off, tp) || tp.offset != 0) {
        return std::nullopt;
    }
    MethodRequestObservation obs;
    obs.src_ip_be = p.src_ip_be;
    obs.src_port = p.src_port;
    obs.service_id = p.h.service_id;
    obs.method_id = p.h.method_id;
    obs.client_id = p.h.client_id;
    obs.session_id = p.h.session_id;
    // This FIRST segment's args chunk only (bytes after the 20-byte segment header);
    // a caller reacting before reassembly needs the correlation fields, and the
    // partial chunk is surfaced for symmetry with parseMethodRequest.
    obs.payload = extractArgs(frame, len, p.someip_off + someiptp::kSegmentHeaderLen, p.udp_total,
                              someiptp::kSegmentHeaderLen);
    return obs;
}

MethodResponder::MethodResponder(std::string_view iface, std::uint16_t service_id,
                                 std::uint16_t method_id, std::uint16_t service_src_port,
                                 MethodReplyBuilder builder)
    : iface_(iface), service_id_(service_id), method_id_(method_id),
      service_src_port_(service_src_port), builder_(std::move(builder)) {
    // SOCK_CLOEXEC so this long-lived CAP_NET_RAW socket is not leaked into a
    // forked child; SOCK_NONBLOCK so onReadable() drains and returns rather than
    // blocking the single capture thread. ETH_P_IP pre-filters to IPv4 frames in
    // the kernel. Mirrors ArpResponder's socket setup.
    sock_ = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(kEtherTypeIpv4));
    if (sock_ < 0) {
        std::fprintf(stderr, "stimulus: MethodResponder socket(AF_PACKET) failed: %s\n",
                     std::strerror(errno));
        return;
    }

    const unsigned int ifindex = ::if_nametoindex(iface_.c_str());
    if (ifindex == 0) {
        std::fprintf(stderr, "stimulus: MethodResponder if_nametoindex('%s') failed: %s\n",
                     iface_.c_str(), std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return;
    }

    sockaddr_ll bind_ll{};
    bind_ll.sll_family = AF_PACKET;
    bind_ll.sll_protocol = htons(kEtherTypeIpv4);
    bind_ll.sll_ifindex = static_cast<int>(ifindex);
    if (::bind(sock_, reinterpret_cast<sockaddr *>(&bind_ll), sizeof(bind_ll)) < 0) {
        std::fprintf(stderr, "stimulus: MethodResponder bind('%s') failed: %s\n", iface_.c_str(),
                     std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return;
    }
    ok_ = true;
}

MethodResponder::~MethodResponder() {
    if (sock_ >= 0) {
        ::close(sock_);
    }
}

void MethodResponder::onReadable() {
    // Drain every frame the kernel has queued on this non-blocking socket,
    // answering each matching Method Request, then return once it would block.
    // Runs on the capture-loop thread, so there is no concurrency with frame
    // dispatch.
    for (;;) {
        std::uint8_t buf[kRxBufLen];
        sockaddr_ll from{};
        socklen_t fromlen = sizeof(from);
        const ssize_t n =
            ::recvfrom(sock_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
        if (n <= 0) {
            break;  // drained (EAGAIN/EWOULDBLOCK) or error — stop this round
        }
        // An AF_PACKET RX socket also sees this interface's egress, including the
        // replies we emit on it; skip our own output so we never parse it.
        if (from.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }
        const auto obs = parseMethodRequest(buf, static_cast<std::size_t>(n), service_id_,
                                            method_id_, service_src_port_);
        if (!obs) {
            continue;
        }
        std::optional<std::vector<std::uint8_t>> reply;
        if (builder_) {
            reply = builder_(*obs);
        }
        if (!reply || reply->empty()) {
            continue;  // builder declined (nullopt), or nothing to send
        }
        const MethodEndpoint client_dest{obs->src_ip_be, obs->src_port};
        if (emitMethodReply(iface_, *reply, service_src_port_, client_dest) == 0) {
            ++replies_sent_;
        }
    }
}

}  // namespace tc8::stimulus
