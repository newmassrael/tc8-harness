// Hermetic cover for connectTcpFromIface (stimulus/tcp_client.h) — the shared TCP
// bind->connect prologue behind the RPC method-request emitters and the
// reliable-subscribe session (incl. its second-source-IP path). Drives it against a
// real loopback listener, so the connect, source-IP bind, local-port readback, the
// case-named source port, and failure sentinels run end-to-end with no DUT and no netns.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>

#include "stimulus/endpoint.h"
#include "stimulus/subscribe_tcp_session.h"
#include "stimulus/tcp_client.h"
#include "tc8/unperformed_stimulus.h"

namespace {

using tc8::stimulus::connectTcpFromIface;
using tc8::stimulus::Endpoint;
using tc8::stimulus::TcpConnectOptions;

// Options naming 127.0.0.1 as the source: the explicit-source-address path, no interface lookup.
TcpConnectOptions fromLoopback() {
    TcpConnectOptions options;
    options.source_ip_be = htonl(INADDR_LOOPBACK);
    return options;
}

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
    TcpConnectOptions options = fromLoopback();
    options.nonblocking = true;
    const int fd = connectTcpFromIface("lo", loopback(listener.port), options, &local_port);
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

    const int rc = connectTcpFromIface("lo", loopback(dead_port), fromLoopback());
    EXPECT_LT(rc, 0);
}

TEST(ConnectTcpFromIface, MissingInterfaceIpReturnsSentinel) {
    // No explicit source IP + a non-existent interface -> no IPv4 to bind -> -2.
    const int rc = connectTcpFromIface("tc8-no-such-if", loopback(9));
    EXPECT_EQ(rc, -2);
}

// A TCP port nothing holds: bind an ephemeral one, read it back, release it.
std::uint16_t aFreeLoopbackPort() {
    const Listener probe = openLoopbackListener();
    const std::uint16_t port = probe.port;
    if (probe.fd >= 0) {
        ::close(probe.fd);
    }
    return port;
}

class NamedSourcePort : public ::testing::Test {
protected:
    void SetUp() override { ::tc8::UnperformedStimulus::reset(); }
    void TearDown() override { ::tc8::UnperformedStimulus::reset(); }
};

TEST_F(NamedSourcePort, TheConnectionLeavesFromThePortTheCaseNamed) {
    const Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);
    const std::uint16_t wanted = aFreeLoopbackPort();
    ASSERT_NE(wanted, 0);

    std::uint16_t local_port = 0;
    TcpConnectOptions options = fromLoopback();
    options.source_port = wanted;
    const int fd = connectTcpFromIface("lo", loopback(listener.port), options, &local_port);
    ASSERT_GE(fd, 0);
    EXPECT_EQ(local_port, wanted);

    // What the DUT sees is what the case asked for: the peer port of the accepted socket.
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    const int accepted = ::accept(listener.fd, reinterpret_cast<sockaddr *>(&peer), &len);
    ASSERT_GE(accepted, 0);
    EXPECT_EQ(ntohs(peer.sin_port), wanted);
    EXPECT_FALSE(::tc8::UnperformedStimulus::any());

    ::close(accepted);
    ::close(fd);
    ::close(listener.fd);
}

TEST_F(NamedSourcePort, ZeroKeepsTheEphemeralBehaviour) {
    const Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);

    std::uint16_t local_port = 0;
    const int fd =
        connectTcpFromIface("lo", loopback(listener.port), fromLoopback(), &local_port);
    ASSERT_GE(fd, 0);
    EXPECT_GT(local_port, 0);

    ::close(fd);
    ::close(listener.fd);
}

TEST_F(NamedSourcePort, APortAnotherSocketHoldsIsAnUnperformedStimulusNotADutFault) {
    const Listener target = openLoopbackListener();
    const Listener holder = openLoopbackListener();  // listening: the port is taken
    ASSERT_GE(target.fd, 0);
    ASSERT_GE(holder.fd, 0);

    TcpConnectOptions options = fromLoopback();
    options.source_port = holder.port;
    const int rc = connectTcpFromIface("lo", loopback(target.port), options);
    EXPECT_EQ(rc, -3);
    EXPECT_TRUE(::tc8::UnperformedStimulus::any())
        << "a connection that never left the tester left no record, so the run would be graded";

    ::close(target.fd);
    ::close(holder.fd);
}

// A connect that is the subject of a case: the peer's answer is a result, not a failure of the
// tester (TcpConnectOptions::peer_verdict_is_outcome).
class PeerVerdict : public ::testing::Test {
protected:
    void SetUp() override { ::tc8::UnperformedStimulus::reset(); }
    void TearDown() override { ::tc8::UnperformedStimulus::reset(); }

    static TcpConnectOptions measuring() {
        TcpConnectOptions options = fromLoopback();
        options.peer_verdict_is_outcome = true;
        return options;
    }
};

TEST_F(PeerVerdict, ARefusedSynIsAPerformedStimulusWithAResult) {
    const std::uint16_t dead_port = aFreeLoopbackPort();
    ASSERT_NE(dead_port, 0);

    std::uint16_t local_port = 0;
    const auto result =
        ::tc8::stimulus::connectTcp("lo", loopback(dead_port), measuring(), &local_port);
    EXPECT_EQ(result.end, ::tc8::stimulus::TcpConnectEnd::kRefused);
    EXPECT_EQ(result.fd, ::tc8::stimulus::kTcpConnectPeerVerdict);
    EXPECT_GT(local_port, 0) << "the SYN carried a port, and the capture names the connection by it";
    EXPECT_FALSE(::tc8::UnperformedStimulus::any())
        << "the SYN went out and the peer refused it: the run has a result to grade";
}

TEST_F(PeerVerdict, TheIntFormReturnsTheVerdictSentinelOnlyWhenAsked) {
    const std::uint16_t dead_port = aFreeLoopbackPort();
    ASSERT_NE(dead_port, 0);

    EXPECT_EQ(connectTcpFromIface("lo", loopback(dead_port), measuring()),
              ::tc8::stimulus::kTcpConnectPeerVerdict);
    EXPECT_FALSE(::tc8::UnperformedStimulus::any());

    // The default is the preamble's: nothing to grade when the connect does not complete.
    EXPECT_EQ(connectTcpFromIface("lo", loopback(dead_port), fromLoopback()), -4);
    EXPECT_TRUE(::tc8::UnperformedStimulus::any());
}

TEST_F(PeerVerdict, ATestersOwnFailureStaysUnperformedEvenWhenAsked) {
    const Listener target = openLoopbackListener();
    const Listener holder = openLoopbackListener();  // listening: the port is taken
    ASSERT_GE(target.fd, 0);
    ASSERT_GE(holder.fd, 0);

    TcpConnectOptions options = measuring();
    options.source_port = holder.port;
    const auto result = ::tc8::stimulus::connectTcp("lo", loopback(target.port), options);
    EXPECT_EQ(result.end, ::tc8::stimulus::TcpConnectEnd::kNotPerformed);
    EXPECT_EQ(result.fd, -3);
    EXPECT_TRUE(::tc8::UnperformedStimulus::any());

    ::close(target.fd);
    ::close(holder.fd);
}

TEST_F(PeerVerdict, ASynTheListenerDropsEndsAtTheCasesOwnBound) {
    // A listener with no room in its accept queue drops further SYNs without answering: the
    // silent peer. backlog 0 holds one completed connection, so the second connect is dropped.
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(fd, 0), 0);
    sockaddr_in got{};
    socklen_t len = sizeof(got);
    ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr *>(&got), &len), 0);
    const std::uint16_t port = ntohs(got.sin_port);

    const int filler = connectTcpFromIface("lo", loopback(port), fromLoopback());
    ASSERT_GE(filler, 0);

    TcpConnectOptions options = measuring();
    options.connect_timeout_ms = 300;
    const auto began = std::chrono::steady_clock::now();
    const auto result = ::tc8::stimulus::connectTcp("lo", loopback(port), options);
    const auto waited = std::chrono::steady_clock::now() - began;
    EXPECT_EQ(result.end, ::tc8::stimulus::TcpConnectEnd::kTimedOut);
    EXPECT_GE(waited, std::chrono::milliseconds(250));
    EXPECT_LT(waited, std::chrono::seconds(5)) << "the kernel's own bound is about two minutes";
    EXPECT_FALSE(::tc8::UnperformedStimulus::any());

    // Without the opt-in the same bound is a failed connect, as the kernel's would be.
    TcpConnectOptions preamble = fromLoopback();
    preamble.connect_timeout_ms = 300;
    EXPECT_EQ(connectTcpFromIface("lo", loopback(port), preamble), -4);
    EXPECT_TRUE(::tc8::UnperformedStimulus::any());

    ::close(filler);
    ::close(fd);
}

TEST_F(PeerVerdict, ABoundedConnectLeavesTheSocketAsBlockingAsAskedFor) {
    const Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);

    TcpConnectOptions options = measuring();
    options.connect_timeout_ms = 1000;
    const auto blocking = ::tc8::stimulus::connectTcp("lo", loopback(listener.port), options);
    ASSERT_EQ(blocking.end, ::tc8::stimulus::TcpConnectEnd::kEstablished);
    EXPECT_EQ(::fcntl(blocking.fd, F_GETFL, 0) & O_NONBLOCK, 0);

    options.nonblocking = true;
    const auto polled = ::tc8::stimulus::connectTcp("lo", loopback(listener.port), options);
    ASSERT_EQ(polled.end, ::tc8::stimulus::TcpConnectEnd::kEstablished);
    EXPECT_NE(::fcntl(polled.fd, F_GETFL, 0) & O_NONBLOCK, 0);

    ::close(blocking.fd);
    ::close(polled.fd);
    ::close(listener.fd);
}

TEST_F(NamedSourcePort, TheSessionHelpersTakeTheSamePort) {
    const Listener listener = openLoopbackListener();
    ASSERT_GE(listener.fd, 0);
    const std::uint16_t wanted = aFreeLoopbackPort();
    ASSERT_NE(wanted, 0);

    ::tc8::stimulus::SubscribeEventgroupTcpSession session("lo", loopback(listener.port),
                                                           htonl(INADDR_LOOPBACK), wanted);
    ASSERT_TRUE(session.valid());
    EXPECT_EQ(session.localPort(), wanted);

    ::close(listener.fd);
}

}  // namespace
