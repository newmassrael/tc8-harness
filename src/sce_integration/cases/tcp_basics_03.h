#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_03_sm.h"

namespace tc8::sce::cases {

using TcpBasics03SM = ::SCE::Generated::tcp_basics_03::tcp_basics_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics03SM>
    : TcpAnyBase<cases::TcpBasics03SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST send an ACK in response to a FIN received in "
        "ESTABLISHED state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:460):
    //   1. TESTER: Cause DUT ESTABLISHED — UT open + connect().
    //   2. TESTER: Send FIN,ACK — shutdown(SHUT_WR) on the client fd.
    //   3. DUT:    Send ACK      — observed on pcap.
    //
    // shutdown(SHUT_WR) leaves the read side open so the tester kernel
    // absorbs any follow-up DUT FIN,ACK without generating a RST. A
    // plain close() would drop the fd's socket state synchronously
    // and any later-arriving DUT segment would RST, which is benign
    // here (we've already observed the ACK) but cleaner to avoid.
    //
    // A 100 ms wait after shutdown lets the DUT's kernel process the
    // FIN and emit the ACK before we proceed to the UT close / teardown.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kBasicsListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        int client_fd = -1;
        connectToDutTcp(cfg, kBasicsListenPort, TcpPostClose::kShutdownWr,
                         &client_fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        if (client_fd >= 0) ::close(client_fd);
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_ack_to_tester_fin_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics03SM, tcp_basics_03)
