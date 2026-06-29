#include "stimulus/tcp_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "stimulus/someip_rpc_builder.h"  // openTcpListener — the bind+listen SSOT.

namespace tc8::stimulus {

namespace {

// Per-call read chunk for the TCP byte stream. NOT a message bound: a SOME/IP
// message longer than this is returned across successive recv() calls (TCP is a
// stream; the Length field, not this buffer, frames messages).
constexpr std::size_t kRecvChunk = 2048;

// Clamp a chrono duration to the int millisecond argument poll() takes; a
// negative/oversized value would otherwise wrap into an unintended timeout.
int pollTimeoutMs(std::chrono::milliseconds timeout) {
    const auto ms = timeout.count();
    if (ms < 0) {
        return 0;
    }
    if (ms > 0x7fffffffLL) {
        return 0x7fffffff;
    }
    return static_cast<int>(ms);
}

// poll() one fd for POLLIN up to `timeout`, retrying on EINTR within the
// remaining budget so a spurious signal does not read as a timeout. Returns 1 if
// readable, 0 on timeout, -1 on a genuine poll error (logged by the caller).
int pollReadable(int fd, std::chrono::milliseconds timeout) {
    auto remaining = timeout;
    const auto start = std::chrono::steady_clock::now();
    for (;;) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, pollTimeoutMs(remaining));
        if (pr >= 0) {
            return pr > 0 ? 1 : 0;
        }
        if (errno != EINTR) {
            return -1;
        }
        // Interrupted: deduct elapsed time and retry until the deadline.
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (elapsed >= timeout) {
            return 0;
        }
        remaining = timeout - elapsed;
    }
}

}  // namespace

// --- TcpConnection ---

TcpConnection::TcpConnection(TcpConnection &&o) noexcept : fd_(o.fd_), peer_(o.peer_) {
    o.fd_ = -1;
}

TcpConnection &TcpConnection::operator=(TcpConnection &&o) noexcept {
    if (this != &o) {
        close();
        fd_ = o.fd_;
        peer_ = o.peer_;
        o.fd_ = -1;
    }
    return *this;
}

TcpConnection::~TcpConnection() { close(); }

void TcpConnection::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

int TcpConnection::send(const std::vector<std::uint8_t> &bytes) {
    if (fd_ < 0) {
        return -1;
    }
    std::size_t off = 0;
    while (off < bytes.size()) {
        // MSG_NOSIGNAL: a DUT that already closed must yield EPIPE here, not a
        // process-killing SIGPIPE.
        const ssize_t n = ::send(fd_, bytes.data() + off, bytes.size() - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::fprintf(stderr, "stimulus: TcpConnection::send failed: %s\n", std::strerror(errno));
            return -1;
        }
        off += static_cast<std::size_t>(n);
    }
    return 0;
}

int TcpConnection::recv(std::vector<std::uint8_t> &out, std::chrono::milliseconds timeout) {
    if (fd_ < 0) {
        return -1;
    }
    const int pr = pollReadable(fd_, timeout);
    if (pr < 0) {
        std::fprintf(stderr, "stimulus: TcpConnection::recv poll failed: %s\n", std::strerror(errno));
        return -1;
    }
    if (pr == 0) {
        return -1;  // timeout, nothing readable (benign — not logged).
    }
    std::uint8_t buf[kRecvChunk];
    const ssize_t n = ::read(fd_, buf, sizeof(buf));
    if (n < 0) {
        std::fprintf(stderr, "stimulus: TcpConnection::recv read failed: %s\n", std::strerror(errno));
        return -1;
    }
    if (n == 0) {
        return 0;  // peer FIN (EOF).
    }
    out.insert(out.end(), buf, buf + n);
    return static_cast<int>(n);
}

bool TcpConnection::waitForPeerFin(std::chrono::milliseconds timeout) {
    if (fd_ < 0) {
        return false;
    }
    // Drain any application bytes the DUT sent before its FIN; recv() == 0 is the
    // FIN. A bounded loop so a peer streaming data cannot hang the wait past
    // `timeout` (the deadline is re-checked each iteration).
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return false;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::vector<std::uint8_t> scratch;
        const int r = recv(scratch, remaining);
        if (r == 0) {
            return true;  // FIN observed.
        }
        if (r < 0) {
            return false;  // timeout / error before any FIN.
        }
        // r > 0: data before the FIN — discard and keep waiting.
    }
}

// --- TcpServer ---

TcpServer::TcpServer(std::string_view iface, std::uint16_t port)
    : listen_fd_(openTcpListener(iface, port)) {}

TcpServer::TcpServer(TcpServer &&o) noexcept : listen_fd_(o.listen_fd_) { o.listen_fd_ = -1; }

TcpServer &TcpServer::operator=(TcpServer &&o) noexcept {
    if (this != &o) {
        closeListener();
        listen_fd_ = o.listen_fd_;
        o.listen_fd_ = -1;
    }
    return *this;
}

TcpServer::~TcpServer() { closeListener(); }

void TcpServer::closeListener() {
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

std::uint16_t TcpServer::port() const {
    if (listen_fd_ < 0) {
        return 0;
    }
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        return 0;
    }
    return ntohs(addr.sin_port);
}

std::optional<TcpConnection> TcpServer::acceptOne(std::chrono::milliseconds timeout) {
    if (listen_fd_ < 0) {
        return std::nullopt;
    }
    const int pr = pollReadable(listen_fd_, timeout);
    if (pr < 0) {
        std::fprintf(stderr, "stimulus: TcpServer::acceptOne poll failed: %s\n", std::strerror(errno));
        return std::nullopt;
    }
    if (pr == 0) {
        return std::nullopt;  // timeout — no connection this window.
    }
    sockaddr_in peer{};
    socklen_t plen = sizeof(peer);
    const int conn_fd = ::accept(listen_fd_, reinterpret_cast<sockaddr *>(&peer), &plen);
    if (conn_fd < 0) {
        std::fprintf(stderr, "stimulus: TcpServer::acceptOne accept failed: %s\n",
                     std::strerror(errno));
        return std::nullopt;
    }
    // peer.sin_addr.s_addr is already network byte order (matches
    // Endpoint::ipv4_be); sin_port is network order, Endpoint::port is host order
    // (the emitter applies htons), so convert once here.
    Endpoint ep{};
    ep.ipv4_be = peer.sin_addr.s_addr;
    ep.port = ntohs(peer.sin_port);
    return TcpConnection{conn_fd, ep};
}

}  // namespace tc8::stimulus
