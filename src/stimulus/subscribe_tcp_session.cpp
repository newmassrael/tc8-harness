#include "stimulus/subscribe_tcp_session.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
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

// The well-known tester-side iptables chain that houses every stimulus
// suppression rule. SHARED BY NAME with tcp_pilot_common.h's TesterAutoRstDrop
// (which jumps it from OUTPUT) and flushed at bring-up by smoke-test.sh, so a
// SIGKILLed harness never leaks a rule into a live hook. This layer cannot include
// the sce-layer constant, so the name is matched here; the two never overlap
// (that chain holds outbound-RST rules keyed on -d DUT, this holds an inbound DROP
// keyed on -s DUT). Kept static to fail closed if iptables is unavailable.
constexpr const char *kTesterStimulusChain = "tc8-stimulus";

std::string dottedIpv4(std::uint32_t ipv4_be) {
    char buf[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &ipv4_be, buf, sizeof(buf));
    return std::string(buf);
}

// Build the iptables match for the DUT->tester direction of one connection: the
// DUT's reliable endpoint as source, this session's tester endpoint as dest.
std::string dropRuleMatch(std::uint32_t dut_ip_be, std::uint16_t dut_port,
                          std::uint32_t tester_ip_be, std::uint16_t tester_port) {
    char m[256];
    std::snprintf(m, sizeof(m),
                  "-p tcp -s %s --sport %u -d %s --dport %u -j DROP",
                  dottedIpv4(dut_ip_be).c_str(), dut_port,
                  dottedIpv4(tester_ip_be).c_str(), tester_port);
    return std::string(m);
}

// Ensure the chain exists and is reached from INPUT (idempotent). Returns true on
// success. The INPUT jump is additive next to tcp_pilot's OUTPUT jump.
bool ensureInputChain() {
    char cmd[192];
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -nL %s >/dev/null 2>&1 || iptables -w 5 -N %s 2>/dev/null",
                  kTesterStimulusChain, kTesterStimulusChain);
    if (std::system(cmd) != 0) {
        return false;
    }
    std::snprintf(cmd, sizeof(cmd),
                  "iptables -w 5 -C INPUT -j %s 2>/dev/null || "
                  "iptables -w 5 -A INPUT -j %s 2>/dev/null",
                  kTesterStimulusChain, kTesterStimulusChain);
    return std::system(cmd) == 0;
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
    if (drop_installed_) {
        resumeIncoming();  // never leak a kernel DROP rule past the session's life.
    }
    if (fd_ >= 0) {
        // close() sends FIN (or RST if unread bytes remain); the DUT tears the
        // reliable subscription down on connection loss.
        ::close(fd_);
        fd_ = -1;
    }
}

void SubscribeEventgroupTcpSession::dropIncoming() {
    if (drop_installed_ || fd_ < 0) {
        return;
    }
    if (!ensureInputChain()) {
        std::fprintf(stderr,
                     "stimulus: reliable subscribe dropIncoming — chain setup failed "
                     "(continuing without the drop filter)\n");
        return;
    }
    const std::string match = dropRuleMatch(dut_reliable_.ipv4_be, dut_reliable_.port,
                                            src_ip_be_, local_port_);
    char cmd[320];
    std::snprintf(cmd, sizeof(cmd), "iptables -w 5 -A %s %s 2>/dev/null",
                  kTesterStimulusChain, match.c_str());
    if (std::system(cmd) == 0) {
        drop_installed_ = true;
    } else {
        std::fprintf(stderr,
                     "stimulus: reliable subscribe dropIncoming install failed "
                     "(continuing without the drop filter)\n");
    }
}

void SubscribeEventgroupTcpSession::resumeIncoming() {
    if (!drop_installed_) {
        return;
    }
    const std::string match = dropRuleMatch(dut_reliable_.ipv4_be, dut_reliable_.port,
                                            src_ip_be_, local_port_);
    char cmd[320];
    std::snprintf(cmd, sizeof(cmd), "iptables -w 5 -D %s %s 2>/dev/null",
                  kTesterStimulusChain, match.c_str());
    const int rc = std::system(cmd);
    (void)rc;
    drop_installed_ = false;
}

void SubscribeEventgroupTcpSession::refuseWithRst() {
    if (fd_ < 0) {
        return;
    }
    // SO_LINGER {on, 0}: close() abandons the send buffer and emits a RST instead
    // of a FIN, so the DUT sees the connection reset immediately (the "refused"
    // shape). Once closed the fd is gone — pollFd() returns -1 and the capture loop
    // stops draining it.
    struct linger lg {};
    lg.l_onoff = 1;
    lg.l_linger = 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    ::close(fd_);
    fd_ = -1;
}

void SubscribeEventgroupTcpSession::applyTeardown(TcpTeardownMode mode) {
    switch (mode) {
        case TcpTeardownMode::kDropIncoming:
            dropIncoming();
            break;
        case TcpTeardownMode::kRefuseWithRst:
            refuseWithRst();
            break;
    }
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
