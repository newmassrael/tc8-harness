#include "stimulus/reliable_method_session.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "stimulus/tcp_client.h"   // connectTcpFromIface — shared TCP bind+connect.
#include "stimulus/tx_observer.h"  // TxScope, reportTxConnected.

namespace tc8::stimulus {

ReliableMethodSession::ReliableMethodSession(std::string_view iface, const Endpoint &dut_reliable,
                                             std::uint16_t source_port)
    : iface_(iface), dut_reliable_(dut_reliable) {
    // No literal fallback: an unconfigured DUT endpoint is a 0.0.0.0:0 sentinel, and
    // connecting somewhere baked in would grade a DUT the case was not pointed at.
    if (dut_reliable.ipv4_be == 0 || dut_reliable.port == 0) {
        std::fprintf(stderr,
                     "stimulus: reliable method session has an unconfigured DUT endpoint "
                     "(0.0.0.0:0) — refusing to connect\n");
        reportTxFailed("reliable_method_session");
        return;
    }
    // Non-blocking after the connect, so onReadable() drains without stalling the
    // single capture thread.
    TcpConnectOptions connect;
    connect.source_port = source_port;
    connect.nonblocking = true;
    const int sock = connectTcpFromIface(iface, dut_reliable, connect);
    if (sock < 0) {
        return;  // connectTcpFromIface logged the failure.
    }
    fd_ = sock;
}

ReliableMethodSession::~ReliableMethodSession() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int ReliableMethodSession::send(const std::vector<SomeIpRpcMessage> &requests) {
    TxScope tx_scope("reliableMethodSessionSend");
    if (fd_ < 0) {
        return -1;
    }
    const std::vector<std::uint8_t> bytes = buildBundledMethodRequests(requests);
    // The socket is non-blocking. A Method Request is tens of bytes against a send
    // buffer of kilobytes on a fresh connection, so a short write is a fault, not
    // back-pressure to wait out.
    const ssize_t n = ::send(fd_, bytes.data(), bytes.size(), MSG_NOSIGNAL);
    if (n < 0 || static_cast<std::size_t>(n) != bytes.size()) {
        const int saved_errno = errno;
        std::fprintf(stderr,
                     "stimulus: reliable method session send(dut:%u) failed: %s (sent=%zd of %zu)\n",
                     dut_reliable_.port, std::strerror(saved_errno), n, bytes.size());
        reportTxFailed("reliable_method_session");
        return -5;
    }
    reportTxConnected("tcp", fd_, bytes.size(), iface_);
    return 0;
}

void ReliableMethodSession::onReadable() {
    if (fd_ < 0 || peer_closed_) {
        return;
    }
    // Drain to EWOULDBLOCK. The bytes are discarded (the verdict is taken from the
    // capture); a recv that returns a pending socket error also clears it, which the
    // busy-spin contract in tc8/pollable_service.h requires.
    std::uint8_t buf[2048];
    for (;;) {
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n > 0) {
            continue;
        }
        if (n == 0) {
            // The DUT closed. The fd stays owned until teardown, but there is
            // nothing more to drain.
            peer_closed_ = true;
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EWOULDBLOCK && errno != EAGAIN) {
            // A reset or other connection error, consumed by this recv: the
            // connection is over, and a dead socket would wake the poll every pass.
            peer_closed_ = true;
        }
        return;
    }
}

}  // namespace tc8::stimulus
