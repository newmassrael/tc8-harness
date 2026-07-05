#include "stimulus/subscribe_tcp_session.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

#include "stimulus/iface_addr.h"  // ipv4OfInterface — tester IPv4 (NBO) SSOT.
#include "stimulus/tcp_client.h"  // connectTcpFromIface — shared TCP bind+connect.

namespace tc8::stimulus {

SubscribeEventgroupTcpSession::SubscribeEventgroupTcpSession(std::string_view iface,
                                                             const Endpoint &dut_reliable,
                                                             std::uint32_t source_ip_be)
    : iface_(iface), dut_reliable_(dut_reliable) {
    // A distinct source IP (a configured tester alias) originates a second client;
    // otherwise use the interface's primary IPv4. Resolved here (not left to the
    // connect primitive) because it is also the source IP advertised in the
    // Subscribe option — testerEndpoint().
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

    // Non-blocking so onReadable() drains without stalling the single capture thread;
    // local_port_ is the connection identity advertised in the Subscribe option.
    const int sock = connectTcpFromIface(iface, dut_reliable, src_ip_be_, &local_port_,
                                         /*nonblocking=*/true);
    if (sock < 0) {
        return;  // connectTcpFromIface logged the failure.
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

int SubscribeEventgroupTcpSession::subscribeParams(SubscribeEventgroupParams params,
                                                   const SubscribeDestination &sd_dest) {
    if (fd_ < 0) {
        return -1;
    }
    // Option 0 — UDP endpoint: default to this session's source SD endpoint
    // (the tester SD port receives the Ack and any unreliable notifications on
    // the mixed eventgroup); a case advertising a distinct endpoint pre-fills it.
    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = src_ip_be_;
        params.tester_endpoint.port = tc8::dut::kSdPort;
        params.tester_endpoint.l4proto = 0x11;
    }
    // Originate the Subscribe from THIS session's source IP so vsomeip binds it
    // to the held connection (a second alias-IP client is then tracked apart).
    return emitSubscribeEventgroupRaw(iface_, std::move(params), sd_dest, src_ip_be_);
}

int SubscribeEventgroupTcpSession::subscribeDualParams(SubscribeEventgroupParams params,
                                                       const SubscribeDestination &sd_dest) {
    // Common dual-transport shape: option 1 is this session's held TCP endpoint
    // and the entry references BOTH options from its first run (#Opt1=2). A case
    // needing a bespoke option-run config (e.g. the two-run ETS_173 phases) sets
    // params.second_endpoint = reliableEndpointOption() itself and calls
    // subscribeParams so it keeps its own index/count overrides.
    setDualEndpointSubscribe(params, reliableEndpointOption());
    return subscribeParams(std::move(params), sd_dest);
}

int SubscribeEventgroupTcpSession::subscribeDual(const SubscribeEventgroupTarget &target,
                                                 const SubscribeDestination &sd_dest) {
    SubscribeEventgroupParams params{};
    params.target = target;
    return subscribeDualParams(std::move(params), sd_dest);
}

int SubscribeEventgroupTcpSession::subscribeMultiParams(MultiSubscribeEventgroupParams params,
                                                        const SubscribeDestination &sd_dest) {
    if (fd_ < 0) {
        return -1;
    }
    // Option 0 — UDP endpoint (default to this session's source SD endpoint);
    // option 1 — this session's held TCP endpoint, so a mixed-reliability entry
    // is matched against the established connection. The caller controls which
    // entries reference the TCP option via per_entry_num_options_first.
    if (params.tester_endpoint.ipv4_be == 0) {
        params.tester_endpoint.ipv4_be = src_ip_be_;
        params.tester_endpoint.port = tc8::dut::kSdPort;
        params.tester_endpoint.l4proto = 0x11;
    }
    params.second_endpoint = reliableEndpointOption();
    return emitMultiSubscribeEventgroupRaw(iface_, std::move(params),
                                           std::chrono::milliseconds(500), sd_dest);
}

int SubscribeEventgroupTcpSession::subscribeMultiDual(
    const std::vector<SubscribeEventgroupTarget> &entries, const SubscribeDestination &sd_dest) {
    MultiSubscribeEventgroupParams params{};
    params.entries = entries;
    return subscribeMultiParams(std::move(params), sd_dest);
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
