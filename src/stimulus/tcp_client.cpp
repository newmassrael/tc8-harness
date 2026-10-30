#include "stimulus/tcp_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "stimulus/iface_addr.h"  // ipv4OfInterface — tester IPv4 (NBO) SSOT.
#include "stimulus/tx_observer.h"

namespace tc8::stimulus {

namespace {

bool setNonBlocking(int sock, bool on) {
    const int flags = ::fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    const int wanted = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    return wanted == flags || ::fcntl(sock, F_SETFL, wanted) == 0;
}

// connect() bounded by `timeout_ms` (0: the kernel's own bound). Returns 0 once the handshake
// completed, else the errno that ended it; ETIMEDOUT when the bound elapsed first. The socket
// is blocking again on return, whatever the outcome.
int connectWithin(int sock, const sockaddr_in &peer, std::uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        return ::connect(sock, reinterpret_cast<const sockaddr *>(&peer), sizeof(peer)) == 0
                   ? 0
                   : errno;
    }
    if (!setNonBlocking(sock, true)) {
        return errno;
    }
    int err = 0;
    if (::connect(sock, reinterpret_cast<const sockaddr *>(&peer), sizeof(peer)) < 0) {
        err = errno;
    }
    if (err == EINPROGRESS) {
        pollfd waiting{sock, POLLOUT, 0};
        int ready;
        do {
            ready = ::poll(&waiting, 1, static_cast<int>(timeout_ms));
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) {
            err = ETIMEDOUT;
        } else if (ready < 0) {
            err = errno;
        } else {
            socklen_t len = sizeof(err);
            if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                err = errno;
            }
        }
    }
    if (err == 0 && !setNonBlocking(sock, false)) {
        err = errno;
    }
    return err;
}

// Whether `err` is the answer of the peer (or its silence) and not a failure of the tester.
bool isPeerVerdict(int err, TcpConnectEnd &end) {
    switch (err) {
        case ECONNREFUSED: end = TcpConnectEnd::kRefused; return true;
        case ECONNRESET:   end = TcpConnectEnd::kReset;   return true;
        case ETIMEDOUT:    end = TcpConnectEnd::kTimedOut; return true;
        default:           return false;
    }
}

TcpConnectResult notPerformed(int sentinel) {
    reportTxFailed("tcp_connect");
    return {sentinel, TcpConnectEnd::kNotPerformed};
}

}  // namespace

TcpConnectResult connectTcp(std::string_view iface, const Endpoint &dst,
                            const TcpConnectOptions &options, std::uint16_t *out_local_port) {
    TC8_TX_SCOPE();
    const std::uint32_t source_ip_be = options.source_ip_be;
    const std::uint16_t source_port = options.source_port;
    const bool nonblocking = options.nonblocking;
    if (out_local_port != nullptr) {
        *out_local_port = 0;
    }

    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: tcp socket() failed: %s\n", std::strerror(errno));
        return notPerformed(-1);
    }

    const std::uint32_t bind_ip = source_ip_be != 0 ? source_ip_be : ipv4OfInterface(iface);
    if (bind_ip == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — cannot bind "
                     "tester source for tcp connect\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return notPerformed(-2);
    }

    if (source_port != 0) {
        // A named source port is one the case may have used a moment ago: let the bind
        // take it while the earlier connection is closing.
        const int on = 1;
        if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            std::fprintf(stderr, "stimulus: tcp SO_REUSEADDR failed: %s\n", std::strerror(errno));
            ::close(sock);
            return notPerformed(-3);
        }
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(source_port);
    bind_addr.sin_addr.s_addr = bind_ip;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        if (source_port != 0) {
            std::fprintf(stderr, "stimulus: tcp bind(source port %u) failed: %s\n", source_port,
                         std::strerror(errno));
        } else {
            std::fprintf(stderr, "stimulus: tcp bind(ephemeral) failed: %s\n", std::strerror(errno));
        }
        ::close(sock);
        return notPerformed(-3);
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(dst.port);
    peer.sin_addr.s_addr = dst.ipv4_be;
    const int connect_err = connectWithin(sock, peer, options.connect_timeout_ms);

    // The ephemeral port the kernel chose is known once the bind has run, so it is read for
    // a connect that failed as well: the SYN carried it.
    std::uint16_t local_port = 0;
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    if (::getsockname(sock, reinterpret_cast<sockaddr *>(&local), &local_len) == 0) {
        local_port = ntohs(local.sin_port);
    }
    if (out_local_port != nullptr) {
        *out_local_port = local_port;
    }

    if (connect_err != 0) {
        std::fprintf(stderr, "stimulus: tcp connect(dut:%u) failed: %s\n", dst.port,
                     std::strerror(connect_err));
        ::close(sock);
        TcpConnectEnd end = TcpConnectEnd::kNotPerformed;
        if (options.peer_verdict_is_outcome && isPeerVerdict(connect_err, end)) {
            // The kernel sent its SYN and the peer answered it, or did not: the stimulus
            // was performed, and what the peer did with it is the measurement.
            reportTcpSynSent(iface, dst.ipv4_be, dst.port, local_port);
            return {kTcpConnectPeerVerdict, end};
        }
        return notPerformed(-4);
    }
    // The SYN and the completing ACK are the kernel's; what the tester did is this
    // connect (tx_observer.h).
    reportTcpConnected(iface, sock);

    if (nonblocking && !setNonBlocking(sock, true)) {
        std::fprintf(stderr, "stimulus: tcp O_NONBLOCK failed: %s\n", std::strerror(errno));
        ::close(sock);
        return notPerformed(-3);
    }

    return {sock, TcpConnectEnd::kEstablished};
}

int connectTcpFromIface(std::string_view iface, const Endpoint &dst,
                        const TcpConnectOptions &options, std::uint16_t *out_local_port) {
    TC8_TX_SCOPE();
    return connectTcp(iface, dst, options, out_local_port).fd;
}

}  // namespace tc8::stimulus
