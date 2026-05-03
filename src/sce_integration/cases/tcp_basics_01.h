#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_01_sm.h"

namespace tc8::sce::cases {

using TcpBasics01SM = ::SCE::Generated::tcp_basics_01::tcp_basics_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics01SM>
    : TcpAnyBase<cases::TcpBasics01SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in LISTEN state MUST send a SYN,ACK in response to a "
        "received SYN (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:399):
    //   1. TESTER: Cause DUT to LISTEN — UT OpOpenTcpSocket on the
    //      well-known port (kBasicsListenPort = 12345).
    //   2. TESTER: Send a SYN — normal socket connect() from the tester
    //      netns. The kernel emits SYN; the handshake completes end-to-
    //      end because no tester-side RST is injected (no raw-inject
    //      path on the listening socket).
    //   3. DUT: Send SYN,ACK — observed on pcap, SCXML gates on
    //      SYN+ACK flags with src_ip == DUT.
    //
    // Socket teardown: connect() is followed by close() so the tester
    // does not hold the connection past the SYN+ACK observation.
    // tc8-dut's acceptor sees the tester's ACK (completion of 3-way), then
    // the tester's FIN (from close), and tears down accordingly. The
    // UT OpCloseTcpSocket still fires so the listener socket frees
    // its resources for the next case on the same worker.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kBasicsListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);
        connectToDutTcp(cfg, kBasicsListenPort, TcpPostClose::kClose);
        // Issue the close UT request best-effort. A tc8-dut that is
        // still processing the socket_id=1 state does not acknowledge
        // before we exit the stimulus, but the UT server thread joins
        // the acceptor on stop() (dtor path), so no listener leaks.
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_syn_ack_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics01SM, tcp_basics_01)
