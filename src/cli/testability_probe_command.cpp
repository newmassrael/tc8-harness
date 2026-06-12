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

}  // namespace

TestabilityProbeCommand::TestabilityProbeCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "testability-probe",
        "Drive a DUT's AUTOSAR Testability Protocol endpoint end to end "
        "(GET_VERSION + START_TEST + UDP data-plane loop + END_TEST)");
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

    // Drive the DUT through the IDutControl seam: lifecycle via the interface,
    // data-plane via the concrete testability engine.
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

    // UDP data-plane loop: CREATE_AND_BIND -> SEND_DATA -> CLOSE_SOCKET, with a
    // tester-side receiver so the emitted datagram is observably confirmed.
    if (!skip_data_ && !cfg.use_tcp) {
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

        // CREATE_AND_BIND (UDP/0x01): doBind=true, localPort=PORT_ANY, localAddr=any.
        std::vector<std::uint8_t> cb;
        cb.push_back(0x01);              // doBind = true
        tp::appendU16(cb, 0xFFFF);       // localPort = PORT_ANY
        tp::appendIpv4Addr(cb, 0);       // localAddr = 0.0.0.0 (any)
        const auto cb_resp = ctrl.call(tp::kGidUdp, tp::kPidCreateAndBind, cb);
        if (!cb_resp.eok() || cb_resp.dat.size() < 2) {
            std::fprintf(stderr,
                         "testability-probe: CREATE_AND_BIND failed (ok=%d rid=0x%02X)\n",
                         cb_resp.ok, cb_resp.rid);
            if (rfd >= 0) ::close(rfd);
            return 1;
        }
        const std::uint16_t socket_id =
            static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);
        std::printf("testability-probe: CREATE_AND_BIND -> E_OK (socketId %u)\n", socket_id);

        // SEND_DATA (UDP/0x02): socketId, totalLen, destPort, destAddr, data.
        static constexpr std::uint8_t kPayload[3] = {'T', 'C', '8'};
        std::vector<std::uint8_t> sd;
        tp::appendU16(sd, socket_id);
        tp::appendU16(sd, sizeof(kPayload));        // totalLen
        tp::appendU16(sd, recv_port);               // destPort
        tp::appendIpv4Addr(sd, tester_ip);          // destAddr (ipxaddr)
        tp::appendVint8(sd, kPayload, sizeof(kPayload));  // data (vint8)
        const auto sd_resp = ctrl.call(tp::kGidUdp, tp::kPidSendData, sd);
        if (!sd_resp.eok()) {
            std::fprintf(stderr, "testability-probe: SEND_DATA failed (ok=%d rid=0x%02X)\n",
                         sd_resp.ok, sd_resp.rid);
            if (rfd >= 0) ::close(rfd);
            return 1;
        }

        bool observed = false;
        if (rfd >= 0 && recv_port != 0) {
            std::uint8_t buf[64];
            const ssize_t n = ::recv(rfd, buf, sizeof(buf), 0);
            observed = (n == static_cast<ssize_t>(sizeof(kPayload)));
        }
        std::printf("testability-probe: SEND_DATA -> E_OK (DUT egress %s)\n",
                    observed ? "observed on tester" : "issued; receipt not confirmed");
        if (rfd >= 0) {
            ::close(rfd);
        }

        // CLOSE_SOCKET (UDP/0x00): socketId.
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, socket_id);
        const auto cs_resp = ctrl.call(tp::kGidUdp, tp::kPidCloseSocket, cs);
        std::printf("testability-probe: CLOSE_SOCKET -> %s (rid=0x%02X)\n",
                    cs_resp.eok() ? "E_OK" : "non-E_OK", cs_resp.rid);
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
