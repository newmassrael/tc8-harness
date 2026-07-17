#include "net/raw_packet_socket.h"

#include "stimulus/arp_builder.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
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
    // One socket per thread, reused across emits, instead of one per frame.
    // The teardown of a per-frame AF_PACKET socket costs a synchronize_net()
    // RCU grace period (measured p50 32 ms) and lands inside whatever cadence
    // the caller is timing — see tc8::net::RawPacketSocket, which is also what
    // the DUT's two emitters now share, so this frame-building path and the
    // firmware cannot drift on how a frame reaches the wire.
    //
    // thread_local, not a bare static: the stimulus runs on the capture thread
    // but nothing in the type's contract promises one. Worst case (a caller
    // alternating interfaces) it re-binds per emit, i.e. exactly the old cost —
    // never worse. Return codes are unchanged: -1 socket, -2 ifindex, -3 send.
    static thread_local ::tc8::net::RawPacketSocket tx;
    const int rc = tx.send(iface, frame.data(), frame.size());
    if (rc < 0) {
        std::fprintf(stderr, "stimulus: raw emit on '%.*s' failed at step %d: %s (%zu B)\n",
                     static_cast<int>(iface.size()), iface.data(), rc, std::strerror(errno),
                     frame.size());
    }
    return rc;
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
