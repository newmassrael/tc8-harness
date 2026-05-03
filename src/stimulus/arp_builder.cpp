#include "stimulus/arp_builder.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace tc8::stimulus {

namespace {

void putBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Emit `ip_be` (already in network byte order) MSB-first. Matches the
// `sendto()` / `inet_pton()` encoding and how `ArpFrame::*_proto_ip` is
// compared against `--expect` values in the parser.
void putIpv4Be(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    b.push_back(static_cast<std::uint8_t>((ip_be >> 0) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 24) & 0xFF));
}

constexpr std::uint16_t kEtherTypeArp = 0x0806;
constexpr std::uint16_t kArpOpRequest = 0x0001;
constexpr std::uint16_t kArpOpReply = 0x0002;

bool isZeroMac(const std::array<std::uint8_t, 6> &m) {
    for (auto b : m) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

}  // namespace

std::vector<std::uint8_t> buildArpFrame(const ArpFrameSpec &spec) {
    const auto &eth_src = isZeroMac(spec.eth_src) ? spec.sender_hw : spec.eth_src;

    std::vector<std::uint8_t> b;
    b.reserve(14 + 8 + 2 * (static_cast<std::size_t>(spec.hw_addr_len) + spec.proto_addr_len));

    // Ethernet II header (14B).
    b.insert(b.end(), spec.eth_dst.begin(), spec.eth_dst.end());
    b.insert(b.end(), eth_src.begin(), eth_src.end());
    putBe16(b, kEtherTypeArp);

    // ARP payload — fixed 8-byte head + variable address pairs.
    putBe16(b, spec.hw_type);
    putBe16(b, spec.proto_type);
    b.push_back(spec.hw_addr_len);
    b.push_back(spec.proto_addr_len);
    putBe16(b, spec.opcode);

    // Address pairs sized by hw_addr_len/proto_addr_len. For RFC 826
    // Ethernet+IPv4 (6/4) this matches the array sizes; for the malformed
    // ARP_21/27 cases (hw/proto type wrong but lengths still 6/4) this
    // also matches. Future support for non-standard lengths would require
    // dynamic-sized address fields in the spec.
    b.insert(b.end(), spec.sender_hw.begin(), spec.sender_hw.end());
    putIpv4Be(b, spec.sender_ip_be);
    b.insert(b.end(), spec.target_hw.begin(), spec.target_hw.end());
    putIpv4Be(b, spec.target_ip_be);

    return b;
}

std::vector<std::uint8_t> buildArpRequest(const std::array<std::uint8_t, 6> &sender_hw, std::uint32_t sender_ip_be,
                                          std::uint32_t target_ip_be) {
    ArpFrameSpec spec;
    spec.opcode = kArpOpRequest;
    spec.sender_hw = sender_hw;
    spec.sender_ip_be = sender_ip_be;
    spec.target_ip_be = target_ip_be;
    return buildArpFrame(spec);
}

std::vector<std::uint8_t> buildGratuitousArpResponse(const std::array<std::uint8_t, 6> &sender_hw,
                                                    std::uint32_t ip_be) {
    ArpFrameSpec spec;
    spec.opcode = kArpOpReply;
    spec.sender_hw = sender_hw;
    spec.target_hw = sender_hw;
    spec.sender_ip_be = ip_be;
    spec.target_ip_be = ip_be;
    return buildArpFrame(spec);
}

int sendRawEthernet(const std::vector<std::uint8_t> &frame, std::string_view iface) {
    const int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket(AF_PACKET) failed: %s\n", std::strerror(errno));
        return -1;
    }

    const unsigned int ifindex = ::if_nametoindex(std::string(iface).c_str());
    if (ifindex == 0) {
        std::fprintf(stderr, "stimulus: if_nametoindex('%.*s') failed: %s\n", static_cast<int>(iface.size()),
                     iface.data(), std::strerror(errno));
        ::close(sock);
        return -2;
    }

    // Read the 16-bit ethertype from the Ethernet-II header at offset
    // 12..13 so this injector works for any L2 frame the stimulus
    // builders emit (ARP 0x0806, IPv4 0x0800, ...). sll_protocol is a
    // hint the kernel passes down to drivers that implement offload/
    // filtering by ethertype; for raw injection on veth the frame's own
    // EtherType field is authoritative, but keeping sll_protocol aligned
    // avoids any ambiguity across iproute/kernel versions.
    std::uint16_t ethertype_host = 0;
    if (frame.size() >= 14) {
        ethertype_host = static_cast<std::uint16_t>((static_cast<std::uint16_t>(frame[12]) << 8) | frame[13]);
    }

    sockaddr_ll dst{};
    dst.sll_family = AF_PACKET;
    dst.sll_protocol = htons(ethertype_host);
    dst.sll_ifindex = static_cast<int>(ifindex);
    dst.sll_halen = 6;
    // sll_addr is the link-layer destination; the kernel uses it when the
    // frame is delivered over interfaces that require it (e.g. hardware
    // MACs on physical adapters). For raw Ethernet injection on veth the
    // destination in the frame header itself is authoritative; copying
    // the first 6 bytes of the frame's eth-dst field keeps both in sync.
    for (int i = 0; i < 6 && i < static_cast<int>(frame.size()); ++i) {
        dst.sll_addr[i] = frame[static_cast<std::size_t>(i)];
    }

    const ssize_t n =
        ::sendto(sock, frame.data(), frame.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(sock);

    if (n < 0 || static_cast<std::size_t>(n) != frame.size()) {
        std::fprintf(stderr, "stimulus: sendto(AF_PACKET %.*s) failed: %s (sent=%zd of %zu)\n",
                     static_cast<int>(iface.size()), iface.data(), std::strerror(saved_errno), n, frame.size());
        return -3;
    }
    return 0;
}

int emitArpLearningBoot(std::string_view iface, std::uint32_t tester_ip_be, std::uint32_t dut_ip_be,
                        ArpLearningVariant variant, const ArpBootTiming &timing) {
    std::this_thread::sleep_for(timing.initial_wait);

    std::vector<std::uint8_t> frame;
    switch (variant) {
    case ArpLearningVariant::Request:
        frame = buildArpRequest(kTesterInjectedMac, tester_ip_be, dut_ip_be);
        break;
    case ArpLearningVariant::GratuitousResponse:
        frame = buildGratuitousArpResponse(kTesterInjectedMac, tester_ip_be);
        break;
    }
    return sendRawEthernet(frame, iface);
}

int emitArpFromTester(std::string_view iface, const ArpFrameSpec &spec, const ArpBootTiming &timing) {
    std::this_thread::sleep_for(timing.initial_wait);
    const auto frame = buildArpFrame(spec);
    return sendRawEthernet(frame, iface);
}

}  // namespace tc8::stimulus
