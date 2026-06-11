#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_07_sm.h"

namespace tc8::sce::cases {

using TcpBasics07SM = ::SCE::Generated::tcp_basics_07::tcp_basics_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics07SM>
    : TcpAnyBase<cases::TcpBasics07SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST progress to ESTABLISHED after receiving SYN,ACK in "
        "SYN-SENT state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:587):
    //   1. TESTER: Cause DUT SYN-SENT — UT OpOpenTcpSocket(Active).
    //   2. TESTER: Send SYN,ACK     — tester kernel listener replies.
    //   3. DUT:    Send ACK         — observed on pcap.
    //   4. TESTER: Verify ESTABLISHED — UT OpQueryTcpEstablished.
    //
    // The auxiliary tester listener replies SYN,ACK to the DUT's SYN
    // automatically as part of Linux's TCP fast-path; the spec does
    // not constrain how the SYN,ACK is produced, only that it arrives
    // and the DUT responds. queryTcpEstablishedSync runs after the
    // handshake has completed (kTcpUtRpcWait + 50 ms covers the
    // SYN→SYN+ACK→ACK round trip on a loaded netns) and writes its
    // result into `c.ut_established` BEFORE the SCXML arms.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics07LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics07LocalOffset);
        (void)listener;

        // queryTcpEstablishedSync reads tc8-dut's TCP_INFO and writes
        // the resulting tristate (0x00 / 0x01 / 0xFF) into Captured
        // before the SCXML arms its assertion on `ut_established == 1`.
        c.ut_established = queryTcpEstablishedSync(
            cfg, /*req_id=*/3, /*socket_id=*/1);

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established";
            case State::Fail_timeout:           return "fail:no_dut_ack_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics07SM, tcp_basics_07)
