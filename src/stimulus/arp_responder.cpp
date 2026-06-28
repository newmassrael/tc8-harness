#include "stimulus/arp_responder.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

#include "stimulus/arp_builder.h"  // ArpFrameSpec / buildArpFrame / sendRawEthernet

namespace tc8::stimulus {

namespace {

constexpr std::uint16_t kEtherTypeArp = 0x0806;
constexpr std::uint16_t kHwTypeEthernet = 0x0001;
constexpr std::uint16_t kProtoTypeIpv4 = 0x0800;
constexpr std::uint16_t kArpOpRequest = 0x0001;
constexpr std::uint16_t kArpOpReply = 0x0002;

// Ethernet-II header is 14 bytes; the Ethernet+IPv4 ARP payload is 28 bytes
// (8-byte fixed head + two 6-byte HW + two 4-byte proto addresses), so the
// smallest frame this can parse is 42 bytes. Captured frames may carry trailing
// padding to the 60-byte Ethernet minimum; only the first 42 are read.
constexpr std::size_t kEthHdrLen = 14;
constexpr std::size_t kArpIpv4FrameLen = 42;

std::uint16_t readBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

// Read 4 wire bytes (network order) into a uint32 in the same network-byte-order
// convention `ArpBinding::ip_be` / `inet_pton` use, so equality holds without a
// host-endianness conversion (memcpy preserves the byte sequence exactly).
std::uint32_t readIpv4Be(const std::uint8_t *p) {
    std::uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

}  // namespace

std::optional<std::vector<std::uint8_t>>
buildArpReplyForRequest(const std::uint8_t *frame, std::size_t len,
                        const std::vector<ArpBinding> &bindings) {
    if (frame == nullptr || len < kArpIpv4FrameLen) {
        return std::nullopt;
    }
    if (readBe16(frame + 12) != kEtherTypeArp) {
        return std::nullopt;
    }
    const std::uint8_t *arp = frame + kEthHdrLen;
    // Only RFC 826 Ethernet/IPv4 Requests with 6/4 address lengths are answered.
    if (readBe16(arp + 0) != kHwTypeEthernet || readBe16(arp + 2) != kProtoTypeIpv4 ||
        arp[4] != 6 || arp[5] != 4 || readBe16(arp + 6) != kArpOpRequest) {
        return std::nullopt;
    }
    // ARP body offsets within `arp`: sender_hw[6]@8, sender_ip[4]@14,
    // target_hw[6]@18, target_ip[4]@24.
    const std::uint8_t *requester_hw = arp + 8;
    const std::uint32_t requester_ip_be = readIpv4Be(arp + 14);
    const std::uint32_t target_ip_be = readIpv4Be(arp + 24);

    for (const auto &b : bindings) {
        if (b.ip_be != target_ip_be) {
            continue;
        }
        std::array<std::uint8_t, 6> req_mac{};
        std::memcpy(req_mac.data(), requester_hw, req_mac.size());

        ArpFrameSpec spec{};
        spec.eth_dst = req_mac;  // unicast the answer back to the requester
        spec.eth_src = b.mac;
        spec.opcode = kArpOpReply;
        spec.sender_hw = b.mac;
        spec.sender_ip_be = b.ip_be;
        spec.target_hw = req_mac;
        spec.target_ip_be = requester_ip_be;
        return buildArpFrame(spec);
    }
    return std::nullopt;
}

ArpResponder::ArpResponder(std::string_view iface, std::vector<ArpBinding> bindings)
    : iface_(iface), bindings_(std::move(bindings)) {
    sock_ = ::socket(AF_PACKET, SOCK_RAW, htons(kEtherTypeArp));
    if (sock_ < 0) {
        std::fprintf(stderr, "stimulus: ArpResponder socket(AF_PACKET) failed: %s\n",
                     std::strerror(errno));
        return;
    }

    const unsigned int ifindex = ::if_nametoindex(iface_.c_str());
    if (ifindex == 0) {
        std::fprintf(stderr, "stimulus: ArpResponder if_nametoindex('%s') failed: %s\n",
                     iface_.c_str(), std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return;
    }

    // Bind to the interface so RX is scoped to it (and the ETH_P_ARP protocol
    // pre-filters non-ARP frames in the kernel).
    sockaddr_ll bind_ll{};
    bind_ll.sll_family = AF_PACKET;
    bind_ll.sll_protocol = htons(kEtherTypeArp);
    bind_ll.sll_ifindex = static_cast<int>(ifindex);
    if (::bind(sock_, reinterpret_cast<sockaddr *>(&bind_ll), sizeof(bind_ll)) < 0) {
        std::fprintf(stderr, "stimulus: ArpResponder bind('%s') failed: %s\n", iface_.c_str(),
                     std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return;
    }

    // eventfd waker: the destructor writes to it to break the worker's poll().
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        std::fprintf(stderr, "stimulus: ArpResponder eventfd failed: %s\n", std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return;
    }

    ok_ = true;
    worker_ = std::thread([this] { run(); });
}

ArpResponder::~ArpResponder() {
    if (ok_) {
        // The worker blocks in poll() with no timeout, so the wake MUST land for
        // it to observe the stop and return — retry across EINTR. An eventfd
        // write of a non-overflowing counter does not otherwise fail.
        const std::uint64_t one = 1;
        while (::write(wake_fd_, &one, sizeof(one)) < 0 && errno == EINTR) {
        }
        if (worker_.joinable()) {
            worker_.join();
        }
    }
    if (wake_fd_ >= 0) {
        ::close(wake_fd_);
    }
    if (sock_ >= 0) {
        ::close(sock_);
    }
}

void ArpResponder::run() {
    pollfd fds[2];
    fds[0].fd = sock_;
    fds[0].events = POLLIN;
    fds[1].fd = wake_fd_;
    fds[1].events = POLLIN;

    for (;;) {
        const int rc = ::poll(fds, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;  // unexpected poll error — stop rather than spin
        }
        if (fds[1].revents & POLLIN) {
            break;  // destructor signalled stop
        }
        if (!(fds[0].revents & POLLIN)) {
            continue;
        }

        std::uint8_t buf[256];
        sockaddr_ll from{};
        socklen_t fromlen = sizeof(from);
        const ssize_t n =
            ::recvfrom(sock_, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
        if (n <= 0) {
            continue;
        }
        // An AF_PACKET RX socket also sees this interface's egress, including
        // our own Replies (sent via sendRawEthernet on the same iface). Skip
        // them so the responder never parses its own output.
        if (from.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }

        const auto reply = buildArpReplyForRequest(buf, static_cast<std::size_t>(n), bindings_);
        if (!reply) {
            continue;
        }
        if (sendRawEthernet(*reply, iface_) == 0) {
            replies_sent_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

}  // namespace tc8::stimulus
