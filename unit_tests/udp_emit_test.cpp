#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

}  // namespace
}  // namespace tc8::stimulus
