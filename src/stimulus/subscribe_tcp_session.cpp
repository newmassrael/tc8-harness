#include "stimulus/subscribe_tcp_session.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "stimulus/iface_addr.h"  // ipv4OfInterface — tester IPv4 (NBO) SSOT.

namespace tc8::stimulus {

namespace {

// Set O_NONBLOCK so the capture loop's onReadable() drain never stalls the
// single-thread model (the IPollableService contract).
bool setNonBlocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

}  // namespace

SubscribeEventgroupTcpSession::SubscribeEventgroupTcpSession(std::string_view iface,
                                                             const Endpoint &dut_reliable,
                                                             std::uint32_t source_ip_be)
    : iface_(iface), dut_reliable_(dut_reliable) {
    // A distinct source IP (a configured tester alias) originates a second client;
    // otherwise use the interface's primary IPv4.
    src_ip_be_ = source_ip_be != 0 ? source_ip_be : ipv4OfInterface(iface);
    if (src_ip_be_ == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — cannot open "
                     "reliable subscribe session\n",
                     static_cast<int>(iface.size()), iface.data());
        return;
    }
    // No literal fallback (cf. MethodEndpoint): an unconfigured DUT endpoint is a
    // 0.0.0.0:0 sentinel — fail loud rather than connect somewhere baked in.
    if (dut_reliable.ipv4_be == 0 || dut_reliable.port == 0) {
        std::fprintf(stderr,
                     "stimulus: reliable subscribe session has an unconfigured DUT "
                     "endpoint (0.0.0.0:0) — refusing to connect\n");
        return;
    }

    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: reliable subscribe socket() failed: %s\n",
                     std::strerror(errno));
        return;
    }

    // Bind the tester source to this session's IPv4 (the iface primary, or a
    // configured alias for a second client) on an ephemeral port, so the connection
    // originates on the tester leg and its source IP is the one advertised in the
    // Subscribe option — mirrors the RPC TCP builders' bind-then-connect idiom.
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = src_ip_be_;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: reliable subscribe bind(ephemeral) failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dut_reliable.port);
    dst.sin_addr.s_addr = dut_reliable.ipv4_be;
    if (::connect(sock, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) < 0) {
        std::fprintf(stderr, "stimulus: reliable subscribe connect(dut:%u) failed: %s\n",
                     dut_reliable.port, std::strerror(errno));
        ::close(sock);
        return;
    }

    // Read back the kernel-assigned source port — the connection identity the DUT
    // keys reliable delivery on, advertised in the Subscribe option below.
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    if (::getsockname(sock, reinterpret_cast<sockaddr *>(&local), &local_len) < 0) {
        std::fprintf(stderr, "stimulus: reliable subscribe getsockname failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return;
    }
    local_port_ = ntohs(local.sin_port);

    if (!setNonBlocking(sock)) {
        std::fprintf(stderr, "stimulus: reliable subscribe O_NONBLOCK failed: %s\n",
                     std::strerror(errno));
        ::close(sock);
        return;
    }

    fd_ = sock;
}

SubscribeEventgroupTcpSession::~SubscribeEventgroupTcpSession() {
    if (fd_ >= 0) {
        // close() sends FIN (or RST if unread bytes remain); on connection loss the
        // DUT is expected to tear the reliable subscription down.
        ::close(fd_);
        fd_ = -1;
    }
}

void SubscribeEventgroupTcpSession::refuseWithRst() {
    if (fd_ < 0) {
        return;
    }
    // SO_LINGER {on, 0}: close() abandons the send buffer and emits a RST instead
    // of a FIN, so the DUT sees the connection reset immediately (the "refused"
    // shape). Once closed the fd is gone — pollFd() returns -1 and the capture loop
    // stops draining it. If SO_LINGER cannot be set, close() would send a graceful
    // FIN instead of a RST — a weaker teardown — so log the downgrade.
    struct linger lg {};
    lg.l_onoff = 1;
    lg.l_linger = 0;
    if (::setsockopt(fd_, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)) < 0) {
        std::fprintf(stderr,
                     "stimulus: reliable subscribe refuseWithRst SO_LINGER failed: %s "
                     "(close will FIN, not RST)\n",
                     std::strerror(errno));
    }
    ::close(fd_);
    fd_ = -1;
}

int SubscribeEventgroupTcpSession::subscribe(const SubscribeEventgroupTarget &target,
                                             const SubscribeDestination &sd_dest) {
    if (fd_ < 0) {
        return -1;
    }
    SubscribeEventgroupParams params{};
    params.target = target;
    params.tester_endpoint.ipv4_be = src_ip_be_;
    params.tester_endpoint.port = local_port_;
    params.tester_endpoint.l4proto = 0x06;  // TCP — bind the subscription to the held connection.
    // Originate the Subscribe datagram from THIS session's source IP so a second
    // client (alias source IP) is a distinct SD sender the DUT tracks separately.
    return emitSubscribeEventgroupRaw(iface_, std::move(params), sd_dest, src_ip_be_);
}

void SubscribeEventgroupTcpSession::onReadable() {
    if (fd_ < 0) {
        return;
    }
    // Drain to EWOULDBLOCK. The bytes are discarded — the verdict is wire-capture
    // based; draining keeps the receive window open and, per the busy-spin
    // contract, consumes any pending socket error (a recv that returns it clears
    // the error so the loop's poll() does not wake on POLLERR every pass).
    std::uint8_t buf[2048];
    for (;;) {
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n > 0) {
            continue;
        }
        if (n == 0) {
            // Peer FIN — the DUT closed. The fd stays owned and is closed at
            // teardown; stop draining.
            break;
        }
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            break;  // fully drained
        }
        if (errno == EINTR) {
            continue;
        }
        // Any other error was just consumed by this recv (clearing the socket
        // error state); stop.
        break;
    }
}

}  // namespace tc8::stimulus
