// Hermetic cover for connectTcpFromIface (stimulus/tcp_client.h) — the shared TCP
// bind->connect prologue behind the RPC method-request emitters and the
// reliable-subscribe session (incl. its second-source-IP path). Drives it against a
// real loopback listener, so the connect, source-IP bind, local-port readback, and
// failure sentinels run end-to-end with no DUT and no netns.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>

#include <gtest/gtest.h>

#include "stimulus/endpoint.h"
#include "stimulus/tcp_client.h"

namespace {

using tc8::stimulus::connectTcpFromIface;
using tc8::stimulus::Endpoint;

// A loopback TCP listener on 127.0.0.1:ephemeral. fd < 0 on failure.
struct Listener {
    int fd = -1;
    std::uint16_t port = 0;
};

Listener openLoopbackListener() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return {};
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0 || ::listen(fd, 1) < 0) {
        ::close(fd);
        return {};
    }
    sockaddr_in got{};
    socklen_t len = sizeof(got);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&got), &len);
    return {fd, ntohs(got.sin_port)};
}

Endpoint loopback(std::uint16_t port) {
    Endpoint e{};
    e.ipv4_be = htonl(INADDR_LOOPBACK);
    e.port = port;
    return e;
}

TEST(ConnectTcpFromIface, ConnectsBindsSourceIpAndReportsLocalPort) {
    const Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);

    std::uint16_t local_port = 0;
    // Explicit source IP (127.0.0.1) exercises the alias/second-client bind path.
    const int fd = connectTcpFromIface("lo", loopback(listener.port),
                                       htonl(INADDR_LOOPBACK), &local_port, /*nonblocking=*/true);
    EXPECT_GE(fd, 0);
    EXPECT_GT(local_port, 0);  // the connection identity a reliable Subscribe advertises

    if (fd >= 0) {
        ::close(fd);
    }
    ::close(listener.fd);
}

TEST(ConnectTcpFromIface, RefusedConnectReturnsNegative) {
    // Open then immediately close a listener: connecting to the now-unbound loopback
    // port is refused, so the connect leg returns its negative sentinel.
    Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);
    const std::uint16_t dead_port = listener.port;
    ::close(listener.fd);

    const int rc = connectTcpFromIface("lo", loopback(dead_port), htonl(INADDR_LOOPBACK));
    EXPECT_LT(rc, 0);
}

TEST(ConnectTcpFromIface, MissingInterfaceIpReturnsSentinel) {
    // No explicit source IP + a non-existent interface -> no IPv4 to bind -> -2.
    const int rc = connectTcpFromIface("tc8-no-such-if", loopback(9));
    EXPECT_EQ(rc, -2);
}

}  // namespace
