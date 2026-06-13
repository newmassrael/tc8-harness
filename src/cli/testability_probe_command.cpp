#include "cli/testability_probe_command.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

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

}  // namespace

TestabilityProbeCommand::TestabilityProbeCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "testability-probe",
        "Drive a DUT's AUTOSAR Testability Protocol endpoint end to end "
        "(GET_VERSION + START_TEST + UDP data-plane loop + optional TCP "
        "active/passive open loops + END_TEST)");
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
}

int TestabilityProbeCommand::run() {
    in_addr addr{};
    if (::inet_pton(AF_INET, dut_ip_.c_str(), &addr) != 1) {
        std::fprintf(stderr, "testability-probe: invalid DUT IPv4 address '%s'\n",
                     dut_ip_.c_str());
        return 1;
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

    // END_TEST (GENERAL/0x03).
    if (!dut.endTest()) {
        std::fprintf(stderr, "testability-probe: END_TEST failed\n");
        return 1;
    }
    std::printf("testability-probe: END_TEST -> E_OK\n");
    return 0;
}

}  // namespace tc8::cli
