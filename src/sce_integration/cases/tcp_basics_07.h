#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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

    // This case verifies the DUT reached ESTABLISHED, which it can only
    // confirm by reading kernel socket state — a capability the opcode UT has
    // (OpQueryTcpEstablished) but the standard AUTOSAR testability protocol
    // does not (no state-introspection SP). Declaring kCapTcpStateProbe makes
    // the CLI capability-skip gate honestly SKIP this case on a testability
    // backend (Tier 2 2b#4) rather than fail it — the standard's limit, not a
    // DUT fault. kCapTcpControl covers the active open itself. This is the
    // first case on the seam whose verdict depends on the state-probe.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    // Spec Test Procedure (v3.0 p281-p300.txt:587):
    //   1. TESTER: Cause DUT SYN-SENT — active OPEN.
    //   2. TESTER: Send SYN,ACK     — tester kernel listener replies.
    //   3. DUT:    Send ACK         — observed on pcap.
    //   4. TESTER: Verify ESTABLISHED — kernel state probe.
    //
    // The auxiliary tester listener replies SYN,ACK to the DUT's SYN
    // automatically as part of Linux's TCP fast-path; the spec does
    // not constrain how the SYN,ACK is produced, only that it arrives
    // and the DUT responds. The state probe runs after the handshake has
    // settled (driveSeamActiveOpen's grace covers the SYN→SYN+ACK→ACK round
    // trip on a loaded netns) and writes its tristate into `c.ut_established`
    // BEFORE the SCXML arms.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics07LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics07LocalOffset);

        if (open.conn) {
            // tcpStateProbe() is non-null by contract: the capability gate
            // skipped this case before stimulus if the backend lacked
            // kCapTcpStateProbe. Map the tristate onto `ut_established` with
            // the same encoding the prior OpQueryTcpEstablished helper used:
            // query failed -> 0xFF, established -> 0x01, not established -> 0x00.
            const auto est = dut.tcpStateProbe()->isEstablished(open.conn->socket);
            c.ut_established = static_cast<std::uint8_t>(
                !est.has_value() ? 0xFF : (*est ? 0x01 : 0x00));
            dut.tcpControl()->closeTcp(open.conn->socket);
        } else {
            c.ut_established = static_cast<std::uint8_t>(0xFF);
        }
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
