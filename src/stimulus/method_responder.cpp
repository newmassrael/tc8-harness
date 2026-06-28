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

}  // namespace

std::optional<MethodRequestObservation>
parseMethodRequest(const std::uint8_t *frame, std::size_t len, std::uint16_t service_id,
                   std::uint16_t method_id, std::uint16_t service_port) {
    if (frame == nullptr || len < kEthHdrLen + kIpv4MinHdrLen + kUdpHdrLen + someip::kHeaderSize) {
        return std::nullopt;
    }
    if (someip::getBe16(frame + 12) != kEtherTypeIpv4) {
        return std::nullopt;
    }
    const std::uint8_t *ip = frame + kEthHdrLen;
    if ((ip[0] >> 4) != 4) {  // IPv4 version nibble
        return std::nullopt;
    }
    // IHL (low nibble of byte 0) gives the IPv4 header length in 32-bit words;
    // IPv4 options push UDP further out, so the extent must be re-checked.
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
    if (ihl < kIpv4MinHdrLen || ip[9] != kIpProtoUdp) {
        return std::nullopt;
    }
    if (len < kEthHdrLen + ihl + kUdpHdrLen + someip::kHeaderSize) {
        return std::nullopt;
    }
    const std::uint8_t *udp = ip + ihl;
    if (someip::getBe16(udp + 2) != service_port) {  // UDP destination port
        return std::nullopt;
    }

    // SOME/IP header via the wire SSOT (the inverse of appendHeader), so the
    // field offsets are not re-spelled here. The extent above guarantees
    // someip::kHeaderSize bytes are present.
    const std::uint8_t *sip = udp + kUdpHdrLen;
    someip::Header h{};
    if (!someip::parseHeader(sip, len - static_cast<std::size_t>(sip - frame), h)) {
        return std::nullopt;
    }
    if (h.service_id != service_id || h.method_id != method_id) {
        return std::nullopt;
    }
    // Only a Request (0x00) is answered; a RequestNoReturn (0x01) gets NO reply
    // per PRS_SOMEIP_00701, and Response/Error/Notification are not ours.
    if (h.message_type != static_cast<std::uint8_t>(someip::MessageType::REQUEST)) {
        return std::nullopt;
    }

    MethodRequestObservation obs;
    obs.src_ip_be = ipv4FromWire(ip + 12);  // IPv4 source address @ +12
    obs.src_port = someip::getBe16(udp + 0);
    obs.service_id = h.service_id;   // read from the frame, not echoed from the args
    obs.method_id = h.method_id;
    obs.client_id = h.client_id;
    obs.session_id = h.session_id;

    // Payload = bytes after the 16-byte SOME/IP header, bounded by the UDP Length
    // field (so Ethernet padding on a sub-60-byte frame is excluded) and clamped
    // to what is physically present (so a malformed over-long length cannot
    // over-read). The SOME/IP Length field is deliberately NOT trusted here.
    const std::size_t payload_off = kEthHdrLen + ihl + kUdpHdrLen + someip::kHeaderSize;
    const std::uint16_t udp_total = someip::getBe16(udp + 4);
    const std::size_t by_udp = (udp_total >= kUdpHdrLen + someip::kHeaderSize)
                                   ? (udp_total - kUdpHdrLen - someip::kHeaderSize)
                                   : 0;
    const std::size_t avail = (len > payload_off) ? (len - payload_off) : 0;
    const std::size_t payload_len = std::min(avail, by_udp);
    obs.payload.assign(frame + payload_off, frame + payload_off + payload_len);
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
