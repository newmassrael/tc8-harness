#include "cli/testability_probe_command.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "sce_integration/dut_control.h"
#include "stimulus/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::cli {

namespace {

namespace tp = ::tc8::testability;

// The local IPv4 the kernel would source a datagram to `dut_ip_be` from —
// found by connecting an unbound UDP socket (no packet sent) and reading back
// the bound address. 0 on failure. Used so SEND_DATA can target a tester-side
// receiver and the loop is self-verifying.
std::uint32_t localAddrToReach(std::uint32_t dut_ip_be) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);  // discard; never contacted
    dst.sin_addr.s_addr = dut_ip_be;
    std::uint32_t out = 0;
    if (::connect(fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) == 0) {
        sockaddr_in local{};
        socklen_t len = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &len) == 0) {
            out = local.sin_addr.s_addr;
        }
    }
    ::close(fd);
    return out;
}

// UDP data-plane loop: CREATE_AND_BIND -> SEND_DATA -> CLOSE_SOCKET, with a
// tester-side receiver so the emitted datagram is observably confirmed. Driven
// through the in-tree typed wrappers (the SP encoding SSOT). false on failure.
bool runUdpDataLoop(const stimulus::TestabilityConfig &cfg, int timeout_ms) {
    const std::uint32_t tester_ip = localAddrToReach(cfg.dut_ip_be);

    // Tester receiver bound to (tester_ip, ephemeral) — the SEND_DATA target.
    const int rfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    std::uint16_t recv_port = 0;
    if (rfd >= 0 && tester_ip != 0) {
        sockaddr_in ra{};
        ra.sin_family = AF_INET;
        ra.sin_addr.s_addr = tester_ip;
        ra.sin_port = 0;
        if (::bind(rfd, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)) == 0) {
            socklen_t rl = sizeof(ra);
            if (::getsockname(rfd, reinterpret_cast<sockaddr *>(&ra), &rl) == 0) {
                recv_port = ntohs(ra.sin_port);
            }
        }
        timeval tv{};
        tv.tv_usec = 300 * 1000;  // 300 ms
        ::setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    const auto socket_id = stimulus::testabilityCreateAndBind(
        cfg, tp::kGidUdp, /*do_bind=*/true, /*local_port=*/0xFFFF, /*local_addr_be=*/0,
        timeout_ms);
    if (!socket_id) {
        std::fprintf(stderr, "testability-probe: UDP CREATE_AND_BIND failed\n");
        if (rfd >= 0) ::close(rfd);
        return false;
    }
    std::printf("testability-probe: UDP CREATE_AND_BIND -> E_OK (socketId %u)\n", *socket_id);

    static constexpr std::uint8_t kPayload[3] = {'T', 'C', '8'};
    const std::vector<std::uint8_t> body(kPayload, kPayload + sizeof(kPayload));
    const auto sd = stimulus::testabilityUdpSendData(cfg, *socket_id, sizeof(kPayload),
                                                     recv_port, tester_ip, body, timeout_ms);
    if (!sd.eok()) {
        std::fprintf(stderr, "testability-probe: UDP SEND_DATA failed (ok=%d rid=0x%02X)\n",
                     sd.ok, sd.rid);
        if (rfd >= 0) ::close(rfd);
        return false;
    }
    bool observed = false;
    if (rfd >= 0 && recv_port != 0) {
        std::uint8_t buf[64];
        const ssize_t n = ::recv(rfd, buf, sizeof(buf), 0);
        observed = (n == static_cast<ssize_t>(sizeof(kPayload)));
    }
    std::printf("testability-probe: UDP SEND_DATA -> E_OK (DUT egress %s)\n",
                observed ? "observed on tester" : "issued; receipt not confirmed");
    if (rfd >= 0) ::close(rfd);

    const auto cs = stimulus::testabilityCloseSocket(cfg, tp::kGidUdp, *socket_id, timeout_ms);
    std::printf("testability-probe: UDP CLOSE_SOCKET -> %s (rid=0x%02X)\n",
                cs.eok() ? "E_OK" : "non-E_OK", cs.rid);
    return true;
}

// TCP active-open loop: a tester-side listener accepts the DUT's CONNECT, so
// reaching ESTABLISHED is observably confirmed; SEND_DATA is then read back on
// the accepted connection. Over the (UDP) control transport. false on failure.
bool runTcpActiveLoop(const stimulus::TestabilityConfig &cfg, int timeout_ms) {
    const std::uint32_t tester_ip = localAddrToReach(cfg.dut_ip_be);

    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    std::uint16_t listen_port = 0;
    if (lfd >= 0 && tester_ip != 0) {
        int on = 1;
        ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in la{};
        la.sin_family = AF_INET;
        la.sin_addr.s_addr = tester_ip;
        la.sin_port = 0;
        if (::bind(lfd, reinterpret_cast<sockaddr *>(&la), sizeof(la)) == 0 &&
            ::listen(lfd, 1) == 0) {
            socklen_t ll = sizeof(la);
            if (::getsockname(lfd, reinterpret_cast<sockaddr *>(&la), &ll) == 0) {
                listen_port = ntohs(la.sin_port);
            }
        }
        timeval tv{};
        tv.tv_sec = 1;  // bound accept()/recv() so a failed connect cannot hang
        ::setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (lfd < 0 || listen_port == 0) {
        std::fprintf(stderr, "testability-probe: TCP listener setup failed\n");
        if (lfd >= 0) ::close(lfd);
        return false;
    }

    const auto sock = stimulus::testabilityCreateAndBind(
        cfg, tp::kGidTcp, /*do_bind=*/false, /*local_port=*/0xFFFF, /*local_addr_be=*/0,
        timeout_ms);
    if (!sock) {
        std::fprintf(stderr, "testability-probe: TCP CREATE_AND_BIND failed\n");
        ::close(lfd);
        return false;
    }
    std::printf("testability-probe: TCP CREATE_AND_BIND -> E_OK (socketId %u)\n", *sock);

    const auto co = stimulus::testabilityTcpConnect(cfg, *sock, listen_port, tester_ip,
                                                    timeout_ms);
    if (!co.eok()) {
        std::fprintf(stderr, "testability-probe: TCP CONNECT failed (ok=%d rid=0x%02X)\n",
                     co.ok, co.rid);
        stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock, timeout_ms);
        ::close(lfd);
        return false;
    }
    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    std::printf("testability-probe: TCP CONNECT -> E_OK (DUT ESTABLISHED %s)\n",
                afd >= 0 ? "observed on tester" : "issued; accept not confirmed");

    static constexpr std::uint8_t kPayload[3] = {'T', 'C', '8'};
    const std::vector<std::uint8_t> body(kPayload, kPayload + sizeof(kPayload));
    const auto sd = stimulus::testabilityTcpSendData(cfg, *sock, sizeof(kPayload),
                                                     /*flags=*/0, body, timeout_ms);
    bool observed = false;
    if (afd >= 0 && sd.eok()) {
        timeval tv{};
        tv.tv_sec = 1;
        ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        std::uint8_t buf[64];
        const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
        observed = (n == static_cast<ssize_t>(sizeof(kPayload)));
    }
    std::printf("testability-probe: TCP SEND_DATA -> %s (DUT egress %s)\n",
                sd.eok() ? "E_OK" : "non-E_OK",
                observed ? "observed on tester" : "issued; receipt not confirmed");
    if (afd >= 0) ::close(afd);
    ::close(lfd);

    const auto cs = stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock, timeout_ms);
    std::printf("testability-probe: TCP CLOSE_SOCKET -> %s (rid=0x%02X)\n",
                cs.eok() ? "E_OK" : "non-E_OK", cs.rid);
    return true;
}

// TCP passive-open loop: bind a DUT listen socket, LISTEN_AND_ACCEPT, then
// connect to it from the tester so the DUT accepts and emits the accept Event.
bool runTcpPassiveLoop(const stimulus::TestabilityConfig &cfg, int timeout_ms) {
    constexpr std::uint16_t kListenPort = 30750;
    const auto listen_sock = stimulus::testabilityCreateAndBind(
        cfg, tp::kGidTcp, /*do_bind=*/true, kListenPort, /*local_addr_be=*/0, timeout_ms);
    if (!listen_sock) {
        std::fprintf(stderr, "testability-probe: TCP CREATE_AND_BIND (listen) failed\n");
        return false;
    }
    std::printf("testability-probe: TCP CREATE_AND_BIND (listen) -> E_OK "
                "(socketId %u, port %u)\n", *listen_sock, kListenPort);

    int cfd = -1;
    const auto ev = stimulus::testabilityTcpListenAndAccept(
        cfg, *listen_sock, /*max_con=*/1,
        [&] {
            // Trigger: the tester connects to the DUT's listen port.
            cfd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (cfd >= 0) {
                sockaddr_in da{};
                da.sin_family = AF_INET;
                da.sin_port = htons(kListenPort);
                da.sin_addr.s_addr = cfg.dut_ip_be;
                if (::connect(cfd, reinterpret_cast<sockaddr *>(&da), sizeof(da)) < 0) {
                    ::close(cfd);
                    cfd = -1;
                }
            }
        },
        timeout_ms);

    bool ok = ev.received;
    if (ev.received) {
        char ab[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &ev.client_addr_be, ab, sizeof(ab));
        std::printf("testability-probe: TCP LISTEN_AND_ACCEPT -> Event "
                    "(newSocketId %u, client %s:%u)\n",
                    ev.new_socket_id, ab, ev.client_port);
        stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, ev.new_socket_id, timeout_ms);
    } else {
        std::fprintf(stderr,
                     "testability-probe: TCP LISTEN_AND_ACCEPT -> no accept Event\n");
    }
    if (cfd >= 0) ::close(cfd);
    stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *listen_sock, timeout_ms);
    return ok;
}

// True if the UTM answers GET_VERSION on `ip_be` within the budget — the
// reachability signal for the ETH loop. Retried briefly so the positive case
// tolerates ARP warm-up; a single short timeout suffices for the negative case.
// Observing the toggle THROUGH the testability protocol itself (rather than a
// re-implemented ICMP/ARP probe) keeps the wire-observation single-sourced.
bool reachableByVersion(const stimulus::TestabilityConfig &base, std::uint32_t ip_be,
                        int per_try_ms, int tries) {
    stimulus::TestabilityConfig cfg = base;
    cfg.dut_ip_be = ip_be;
    for (int i = 0; i < tries; ++i) {
        if (stimulus::testabilityGetVersion(cfg, per_try_ms)) {
            return true;
        }
    }
    return false;
}

// Per-attempt budget for a reachability observation: half the SP timeout, capped at
// 300 ms so a long SP timeout doesn't stretch each observe poll. Shared by the ETH
// and IP STATIC loops.
int observeBudgetMs(int timeout_ms) { return std::min(timeout_ms / 2, 300); }

// ETH INTERFACE_DOWN / INTERFACE_UP loop (GID 0x0B): command the DUT to take a
// SECONDARY interface down then back up over the PRIMARY control channel, and
// OBSERVE the effect — the DUT becomes unreachable on the secondary IP while the
// down primary stays alive (every E_OK returns), then reachable again. This is a
// strictly stronger claim than E_OK alone: ETH's effect, unlike ICMP's, is
// observable, so the probe observes it. `eth_iface` is the DUT-side interface
// name to toggle; `observe_ip_be` is the DUT's IP on a different interface.
bool runEthInterfaceLoop(const stimulus::TestabilityConfig &cfg, const std::string &eth_iface,
                         std::uint32_t observe_ip_be, int timeout_ms) {
    char ob[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &observe_ip_be, ob, sizeof(ob));
    // Short per-try budget so the negative (unreachable) observation does not
    // wait the full control timeout; a few tries cover ARP warm-up when up.
    const int obs_ms = observeBudgetMs(timeout_ms);

    if (!reachableByVersion(cfg, observe_ip_be, obs_ms, 5)) {
        std::fprintf(stderr,
                     "testability-probe: ETH precondition failed — %s not reachable before toggle "
                     "(is the secondary interface up?)\n",
                     ob);
        return false;
    }
    std::printf("testability-probe: ETH precondition -> %s reachable (secondary up)\n", ob);

    const auto down = stimulus::testabilityInterfaceDown(cfg, eth_iface, timeout_ms);
    if (!down.eok()) {
        std::fprintf(stderr, "testability-probe: ETH INTERFACE_DOWN(%s) failed (ok=%d rid=0x%02X)\n",
                     eth_iface.c_str(), down.ok, down.rid);
        return false;
    }
    if (reachableByVersion(cfg, observe_ip_be, obs_ms, 3)) {
        std::fprintf(stderr,
                     "testability-probe: ETH INTERFACE_DOWN reported E_OK but %s still reachable "
                     "— the link did not go down\n",
                     ob);
        return false;
    }
    std::printf("testability-probe: ETH INTERFACE_DOWN(%s) -> E_OK (%s now unreachable)\n",
                eth_iface.c_str(), ob);

    const auto up = stimulus::testabilityInterfaceUp(cfg, eth_iface, timeout_ms);
    if (!up.eok()) {
        std::fprintf(stderr, "testability-probe: ETH INTERFACE_UP(%s) failed (ok=%d rid=0x%02X)\n",
                     eth_iface.c_str(), up.ok, up.rid);
        return false;
    }
    if (!reachableByVersion(cfg, observe_ip_be, obs_ms, 10)) {
        std::fprintf(stderr,
                     "testability-probe: ETH INTERFACE_UP reported E_OK but %s did not become "
                     "reachable again\n",
                     ob);
        return false;
    }
    std::printf("testability-probe: ETH INTERFACE_UP(%s) -> E_OK (%s reachable again)\n",
                eth_iface.c_str(), ob);
    return true;
}

// IP STATIC_ADDRESS / STATIC_ROUTE loop (GID 0x05): command the DUT to assign a
// FRESH IPv4 address to a SECONDARY interface over the PRIMARY control channel and
// OBSERVE the effect — the new address, unreachable before, answers GET_VERSION
// after (the UTM binds INADDR_ANY, so it replies on every DUT IP). Then, when route
// params are given, command STATIC_ROUTE and assert E_OK (the route's presence in
// the DUT's table is observed by the check script, which holds netns access). Like
// the ETH loop, STATIC_ADDRESS's effect is observable, so the probe observes it.
bool runIpStaticLoop(const stimulus::TestabilityConfig &cfg, const std::string &iface,
                     std::uint32_t new_addr_be, std::uint8_t cidr, bool do_route,
                     std::uint32_t route_subnet_be, std::uint8_t route_cidr,
                     std::uint32_t route_gw_be, int timeout_ms) {
    char nb[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &new_addr_be, nb, sizeof(nb));
    const int obs_ms = observeBudgetMs(timeout_ms);

    // Precondition: the address to assign is not already live, so reachability
    // AFTER the assignment is unambiguous evidence the SP took effect.
    if (reachableByVersion(cfg, new_addr_be, obs_ms, 3)) {
        std::fprintf(stderr,
                     "testability-probe: IP precondition failed — %s already reachable before "
                     "STATIC_ADDRESS (pick an unused address)\n",
                     nb);
        return false;
    }
    std::printf("testability-probe: IP precondition -> %s not yet assigned\n", nb);

    const auto sa = stimulus::testabilityStaticAddress(cfg, iface, new_addr_be, cidr, timeout_ms);
    if (!sa.eok()) {
        std::fprintf(stderr,
                     "testability-probe: IP STATIC_ADDRESS(%s, %s/%u) failed (ok=%d rid=0x%02X)\n",
                     iface.c_str(), nb, cidr, sa.ok, sa.rid);
        return false;
    }
    if (!reachableByVersion(cfg, new_addr_be, obs_ms, 10)) {
        std::fprintf(stderr,
                     "testability-probe: IP STATIC_ADDRESS reported E_OK but %s did not become "
                     "reachable — the address was not assigned\n",
                     nb);
        return false;
    }
    std::printf("testability-probe: IP STATIC_ADDRESS(%s) -> E_OK (%s/%u now reachable)\n",
                iface.c_str(), nb, cidr);

    if (do_route) {
        char sb[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, &route_subnet_be, sb, sizeof(sb));
        const auto sr = stimulus::testabilityStaticRoute(cfg, iface, route_subnet_be, route_cidr,
                                                         route_gw_be, timeout_ms);
        if (!sr.eok()) {
            std::fprintf(stderr,
                         "testability-probe: IP STATIC_ROUTE(%s/%u) failed (ok=%d rid=0x%02X)\n",
                         sb, route_cidr, sr.ok, sr.rid);
            return false;
        }
        std::printf("testability-probe: IP STATIC_ROUTE(%s/%u dev %s) -> E_OK "
                    "(table presence observed by the check script)\n",
                    sb, route_cidr, iface.c_str());
    }
    return true;
}

// ICMP echo loop: command the DUT's testability endpoint to emit an ICMP Echo
// Request toward the tester and confirm the endpoint accepted it (E_OK). Like
// ut-ping, this is a liveness / integration smoke of the SP round-trip — it is
// deliberately NOT a wire observer. ICMP cannot be endpoint-received the way the
// UDP/TCP loops are (the kernel intercepts Echo Requests and answers them on the
// application's behalf), so E_OK is the strongest claim this CLI can make
// honestly. Observing the emitted Echo Request on the wire is the job of the
// framework conformance case, which reuses the shared ICMP dissector / Captured
// / SCXML path rather than minting a second observer here. false on non-E_OK.
bool runIcmpEchoLoop(const stimulus::TestabilityConfig &cfg, int timeout_ms) {
    const std::uint32_t tester_ip = localAddrToReach(cfg.dut_ip_be);

    static constexpr std::uint8_t kPayload[3] = {'T', 'C', '8'};
    const std::vector<std::uint8_t> payload(kPayload, kPayload + sizeof(kPayload));
    // ifName empty => "any" (the DUT's default egress); destAddr = the tester.
    const auto er = stimulus::testabilityEchoRequest(cfg, /*iface=*/"", tester_ip, payload,
                                                     timeout_ms);
    if (!er.eok()) {
        std::fprintf(stderr, "testability-probe: ICMP ECHO_REQUEST failed (ok=%d rid=0x%02X)\n",
                     er.ok, er.rid);
        return false;
    }
    char tb[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &tester_ip, tb, sizeof(tb));
    std::printf("testability-probe: ICMP ECHO_REQUEST -> E_OK (Echo Request issued toward %s)\n",
                tb);
    return true;
}

}  // namespace

TestabilityProbeCommand::TestabilityProbeCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "testability-probe",
        "Drive a DUT's AUTOSAR Testability Protocol endpoint end to end "
        "(GET_VERSION + START_TEST + UDP data-plane loop + optional TCP "
        "active/passive open loops + optional ICMP echo loop + END_TEST)");
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 address")->required();
    sub_->add_option("--port", port_,
                     "Testability UDP/TCP port (default: protocol constant 30700)");
    sub_->add_option("--service-id", service_id_,
                     "Testability Service ID (default: 0x0105)");
    sub_->add_option("-t,--timeout", timeout_ms_, "Reply timeout in milliseconds")
        ->capture_default_str();
    sub_->add_flag("--tcp", use_tcp_, "Carry SOME/IP over TCP instead of UDP");
    sub_->add_flag("--no-data", skip_data_,
                   "Probe only the GENERAL lifecycle (skip the UDP data-plane loop)");
    sub_->add_flag("--tcp-data", tcp_data_,
                   "Also exercise the TCP-group active- and passive-open SP loops");
    sub_->add_flag("--icmp", icmp_echo_,
                   "Also exercise the ICMP-group ECHO_REQUEST SP loop");
    sub_->add_flag("--eth", eth_,
                   "Also exercise the ETH-group INTERFACE_DOWN/UP SP loop "
                   "(requires --eth-iface and --eth-observe-ip)");
    sub_->add_option("--eth-iface", eth_iface_,
                     "DUT-side interface name the ETH loop toggles (with --eth)");
    sub_->add_option("--eth-observe-ip", eth_observe_ip_,
                     "DUT IPv4 on a second interface whose reachability the ETH loop "
                     "watches to observe the toggle (with --eth)");
    sub_->add_flag("--ip-static", ip_static_,
                   "Also exercise the IP-group STATIC_ADDRESS/STATIC_ROUTE SP loop "
                   "(requires --ip-static-iface and --ip-static-addr)");
    sub_->add_option("--ip-static-iface", ip_static_iface_,
                     "DUT-side secondary interface the STATIC loop reconfigures (with --ip-static)");
    sub_->add_option("--ip-static-addr", ip_static_addr_,
                     "Fresh IPv4 the loop assigns and observes reachable (with --ip-static)");
    sub_->add_option("--ip-static-cidr", ip_static_cidr_,
                     "CIDR prefix length for --ip-static-addr (default 24)");
    sub_->add_option("--ip-static-route-subnet", ip_static_route_subnet_,
                     "Optional STATIC_ROUTE destination subnet (with --ip-static)");
    sub_->add_option("--ip-static-route-gw", ip_static_route_gw_,
                     "STATIC_ROUTE gateway (required with --ip-static-route-subnet)");
    sub_->add_option("--ip-static-route-cidr", ip_static_route_cidr_,
                     "CIDR prefix length for --ip-static-route-subnet (default 24)");
}

int TestabilityProbeCommand::run() {
    in_addr addr{};
    if (::inet_pton(AF_INET, dut_ip_.c_str(), &addr) != 1) {
        std::fprintf(stderr, "testability-probe: invalid DUT IPv4 address '%s'\n",
                     dut_ip_.c_str());
        return 1;
    }

    // Validate the ETH loop's parameters up front, before any DUT-mutating
    // lifecycle (START_TEST) runs, so a misconfigured invocation fails fast.
    std::uint32_t eth_observe_be = 0;
    if (eth_) {
        in_addr obs{};
        if (eth_iface_.empty() || eth_observe_ip_.empty()) {
            std::fprintf(stderr,
                         "testability-probe: --eth requires --eth-iface and --eth-observe-ip\n");
            return 1;
        }
        if (::inet_pton(AF_INET, eth_observe_ip_.c_str(), &obs) != 1) {
            std::fprintf(stderr, "testability-probe: invalid --eth-observe-ip '%s'\n",
                         eth_observe_ip_.c_str());
            return 1;
        }
        eth_observe_be = obs.s_addr;
    }

    // Validate the IP STATIC loop's parameters up front too (fail fast before any
    // DUT-mutating lifecycle runs).
    std::uint32_t ip_static_addr_be = 0;
    std::uint32_t ip_route_subnet_be = 0;
    std::uint32_t ip_route_gw_be = 0;
    bool ip_do_route = false;
    if (ip_static_) {
        if (ip_static_iface_.empty() || ip_static_addr_.empty()) {
            std::fprintf(
                stderr,
                "testability-probe: --ip-static requires --ip-static-iface and --ip-static-addr\n");
            return 1;
        }
        in_addr a{};
        if (::inet_pton(AF_INET, ip_static_addr_.c_str(), &a) != 1) {
            std::fprintf(stderr, "testability-probe: invalid --ip-static-addr '%s'\n",
                         ip_static_addr_.c_str());
            return 1;
        }
        ip_static_addr_be = a.s_addr;
        if (ip_static_cidr_ < 0 || ip_static_cidr_ > 32) {
            std::fprintf(stderr, "testability-probe: --ip-static-cidr must be 0..32\n");
            return 1;
        }
        if (!ip_static_route_subnet_.empty()) {
            in_addr sn{};
            in_addr gw{};
            if (::inet_pton(AF_INET, ip_static_route_subnet_.c_str(), &sn) != 1 ||
                ip_static_route_gw_.empty() ||
                ::inet_pton(AF_INET, ip_static_route_gw_.c_str(), &gw) != 1 ||
                ip_static_route_cidr_ < 0 || ip_static_route_cidr_ > 32) {
                std::fprintf(stderr,
                             "testability-probe: --ip-static-route-subnet needs a valid subnet, "
                             "--ip-static-route-gw, and a 0..32 --ip-static-route-cidr\n");
                return 1;
            }
            ip_route_subnet_be = sn.s_addr;
            ip_route_gw_be = gw.s_addr;
            ip_do_route = true;
        }
    }

    stimulus::TestabilityConfig cfg;
    cfg.dut_ip_be = addr.s_addr;
    cfg.dut_port = port_ > 0 ? static_cast<std::uint16_t>(port_) : tp::kDefaultPort;
    cfg.service_id =
        service_id_ >= 0 ? static_cast<std::uint16_t>(service_id_) : tp::kDefaultServiceId;
    cfg.use_tcp = use_tcp_;

    // Lifecycle goes through the IDutControl seam (backend-agnostic); data-plane
    // service primitives use the typed free-function wrappers with cfg.
    sce::TestabilityControl ctrl(cfg, timeout_ms_);
    sce::IDutControl &dut = ctrl;

    // GET_VERSION (GENERAL/0x01) — also the channel-liveness probe.
    const auto version = ctrl.getVersion();
    if (!version) {
        std::fprintf(stderr,
                     "testability-probe: no GET_VERSION reply from %s:%u within %d ms "
                     "(DUT down, testability not implemented, or port/service-id "
                     "mismatch)\n",
                     dut_ip_.c_str(), cfg.dut_port, timeout_ms_);
        return 1;
    }
    std::printf("testability-probe: %s:%u answered [%s] — testability protocol v%u.%u.%u "
                "(service-id 0x%04X)\n",
                dut_ip_.c_str(), cfg.dut_port, dut.backendName(), version->major,
                version->minor, version->patch, cfg.service_id);

    // START_TEST (GENERAL/0x02).
    if (!dut.startTest()) {
        std::fprintf(stderr, "testability-probe: START_TEST failed\n");
        return 1;
    }
    std::printf("testability-probe: START_TEST -> E_OK\n");

    if (!skip_data_ && !cfg.use_tcp) {
        if (!runUdpDataLoop(cfg, timeout_ms_)) {
            return 1;
        }
    }
    if (tcp_data_) {
        if (!runTcpActiveLoop(cfg, timeout_ms_) || !runTcpPassiveLoop(cfg, timeout_ms_)) {
            return 1;
        }
    }
    if (icmp_echo_) {
        if (!runIcmpEchoLoop(cfg, timeout_ms_)) {
            return 1;
        }
    }
    if (eth_) {
        if (!runEthInterfaceLoop(cfg, eth_iface_, eth_observe_be, timeout_ms_)) {
            return 1;
        }
    }
    if (ip_static_) {
        if (!runIpStaticLoop(cfg, ip_static_iface_, ip_static_addr_be,
                             static_cast<std::uint8_t>(ip_static_cidr_), ip_do_route,
                             ip_route_subnet_be, static_cast<std::uint8_t>(ip_static_route_cidr_),
                             ip_route_gw_be, timeout_ms_)) {
            return 1;
        }
    }

    // END_TEST (GENERAL/0x03).
    if (!dut.endTest()) {
        std::fprintf(stderr, "testability-probe: END_TEST failed\n");
        return 1;
    }
    std::printf("testability-probe: END_TEST -> E_OK\n");
    return 0;
}

}  // namespace tc8::cli
