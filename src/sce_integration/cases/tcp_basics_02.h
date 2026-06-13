#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_02_sm.h"

namespace tc8::sce::cases {

using TcpBasics02SM = ::SCE::Generated::tcp_basics_02::tcp_basics_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics02SM>
    : TcpAnyBase<cases::TcpBasics02SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST move on to ESTABLISHED state after receiving ACK in "
        "SYN-RCVD state (RFC 793 §3.2 p23 Terminology)";

    // This case's verdict rests on confirming the DUT reached ESTABLISHED,
    // which it can only do by reading kernel socket state — a capability the
    // opcode UT has (OpQueryTcpEstablished) but the standard AUTOSAR
    // testability protocol does not (no state-introspection SP). Declaring
    // kCapTcpStateProbe makes the CLI capability-skip gate honestly SKIP this
    // case on a testability backend (Tier 2 2b#4) rather than fail it — the
    // standard's limit, not a DUT fault. kCapTcpControl covers the passive open
    // itself.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpStateProbe;

    // Spec Test Procedure (v3.0 p281-p300.txt:428):
    //   1. TESTER: Send a SYN   — passive open on the DUT, then a kernel
    //              connect() emits the SYN.
    //   2. DUT:    Send SYN,ACK — observed on pcap.
    //   3. TESTER: Send an ACK  — the kernel completes the handshake.
    //   4. TESTER: Verify DUT at ESTABLISHED — kernel state probe.
    //
    // Migrated onto the Tier-2 DUT-control seam: the passive open runs through
    // `driveSeamPassiveOpen` (ITcpControl::acceptTcp), and the ESTABLISHED
    // check through `tcpStateProbe()->isEstablished`. The tester connection is
    // kept open across the probe (the seam returns its fd) so the DUT's
    // accepted socket does not race a tester-side RST before the query reads
    // its state. The probe's tristate lands in `c.ut_established` BEFORE the
    // SCXML reads it on the first tcp_observed edge (the kernel-buffered
    // SYN,ACK). Close happens after: the tester fd, then the DUT socket via the
    // seam.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamPassiveOpen(dut, cfg, kBasicsListenPort);

        if (open.conn) {
            // tcpStateProbe() is non-null by contract: the capability gate
            // skipped this case before stimulus if the backend lacked
            // kCapTcpStateProbe. Map the tristate onto `ut_established` with the
            // same encoding the prior OpQueryTcpEstablished helper used: query
            // failed -> 0xFF, established -> 0x01, not established -> 0x00.
            const auto est = dut.tcpStateProbe()->isEstablished(open.conn->socket);
            c.ut_established = static_cast<std::uint8_t>(
                !est.has_value() ? 0xFF : (*est ? 0x01 : 0x00));
        } else {
            c.ut_established = static_cast<std::uint8_t>(0xFF);
        }

        if (open.tester_fd >= 0) ::close(open.tester_fd);
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established";
            case State::Fail_timeout:           return "fail:no_dut_syn_ack_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics02SM, tcp_basics_02)
