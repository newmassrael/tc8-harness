#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/udp_emit.h"

namespace tc8::stimulus {
namespace {

// The defining property of the emitter: the datagram leaves from the
// caller-chosen source port. Send over loopback to an ephemeral receiver and
// read back the source port the kernel stamped on the received datagram.
TEST(UdpEmit, UnicastUsesChosenSourcePort) {
    const int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rx, 0);

    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;  // let the kernel pick the receiver port
    ASSERT_EQ(::bind(rx, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);

    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ASSERT_EQ(::getsockname(rx, reinterpret_cast<sockaddr *>(&bound), &bl), 0);
    const std::uint16_t rx_port = ntohs(bound.sin_port);

    // Bounded receive so a dropped datagram fails the test instead of hanging.
    timeval tv{1, 0};
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // A fixed source port below the ephemeral range, so the OS will not have
    // auto-assigned it to some other socket.
    const std::uint16_t kChosenSrc = 23456;
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const int rc = sendUdpUnicast(payload, "lo", kChosenSrc, htonl(INADDR_LOOPBACK), rx_port);
    ASSERT_EQ(rc, 0);

    std::uint8_t buf[64] = {};
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    const ssize_t n = ::recvfrom(rx, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fl);
    ::close(rx);

    ASSERT_EQ(n, static_cast<ssize_t>(payload.size()));
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), payload);
    EXPECT_EQ(ntohs(from.sin_port), kChosenSrc);
}

// An interface with no IPv4 address surfaces as the documented -2 sentinel,
// not a crash or a silent success.
TEST(UdpEmit, UnknownInterfaceReturnsSentinel) {
    const std::vector<std::uint8_t> payload = {0x01};
    const int rc = sendUdpUnicast(payload, "tc8-no-such-if", 23457, htonl(INADDR_LOOPBACK), 9999);
    EXPECT_EQ(rc, -2);
}

// The multicast path's own validation: a malformed group address surfaces as the
// documented -5 (inet_pton failure) after the bind + IP_MULTICAST_IF/TTL setup,
// rather than sending to a garbage destination. Deterministic — no multicast
// delivery required.
TEST(UdpEmit, MulticastRejectsMalformedGroup) {
    const std::vector<std::uint8_t> payload = {0x01};
    const int rc = sendUdpMulticast(payload, "lo", 23458, "not.an.ip.address", 9999);
    EXPECT_EQ(rc, -5);
}

// The source-IP emit's wire layout: the built frame must carry the chosen
// IPv4 source address (so the DUT discriminates clients by Sender IP) and the
// chosen MACs, ports, and payload. Pure builder, so this is hermetic.
TEST(UdpEmit, BuildUdpFromSourceIpFrameLayout) {
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::uint32_t src_ip = ::inet_addr("172.16.0.5");  // network byte order
    const std::uint32_t dst_ip = ::inet_addr("172.16.0.1");
    const std::array<std::uint8_t, 6> dut_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const std::array<std::uint8_t, 6> tester_mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

    const std::vector<std::uint8_t> f =
        buildUdpFromSourceIpFrame(payload, src_ip, 40000, dst_ip, 30509, dut_mac, tester_mac);

    // Ethernet(14) + IPv4(20) + UDP(8) + payload(4).
    ASSERT_EQ(f.size(), 14u + 20u + 8u + payload.size());
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(f[static_cast<std::size_t>(i)], dut_mac[static_cast<std::size_t>(i)]) << "eth dst " << i;
        EXPECT_EQ(f[static_cast<std::size_t>(6 + i)], tester_mac[static_cast<std::size_t>(i)]) << "eth src " << i;
    }
    EXPECT_EQ(f[12], 0x08);  // EtherType IPv4 0x0800
    EXPECT_EQ(f[13], 0x00);
    EXPECT_EQ(f[23], 0x11);  // IP protocol = UDP
    // IPv4 source = 172.16.0.5, destination = 172.16.0.1 (on the wire).
    EXPECT_EQ(f[26], 0xAC);
    EXPECT_EQ(f[27], 0x10);
    EXPECT_EQ(f[28], 0x00);
    EXPECT_EQ(f[29], 0x05);
    EXPECT_EQ(f[30], 0xAC);
    EXPECT_EQ(f[33], 0x01);
    // UDP source 40000 (0x9C40) / destination 30509 (0x772D), big-endian.
    EXPECT_EQ(f[34], 0x9C);
    EXPECT_EQ(f[35], 0x40);
    EXPECT_EQ(f[36], 0x77);
    EXPECT_EQ(f[37], 0x2D);
    // L7 payload follows the 8-byte UDP header.
    EXPECT_EQ(f[42], 0xDE);
    EXPECT_EQ(f[45], 0xEF);
}

}  // namespace
}  // namespace tc8::stimulus
