#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_06_sm.h"

namespace tc8::sce::cases {

using TcpBasics06SM = ::SCE::Generated::tcp_basics_06::tcp_basics_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics06SM>
    : TcpAnyBase<cases::TcpBasics06SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSED state MUST send a SYN on an active OPEN call "
        "(RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:558):
    //   1. TESTER: Cause DUT app to issue active OPEN — UT
    //              OpOpenTcpSocket(Active).
    //   2. DUT:    Send a SYN — observed on pcap.
    //
    // Mechanism: the tester first arms an auxiliary kernel listener on
    // `kBasicsActiveRemotePort` so the DUT's outbound SYN reaches a
    // real receiver instead of the tester-kernel's RST-on-closed-port
    // path. The active OPEN is then driven through the Tier-2 DUT-control
    // seam (`IDutControl::tcpControl()->connectTcp`), which spawns the
    // DUT's connect() worker — emitting the SYN observed by SCXML — on
    // whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). This is the first pilot case migrated onto the seam:
    // the same case runs against a standard testability DUT with config
    // only, the Tier-2 North Star (see
    // claudedocs/testability_seam_tier2_design.md).
    //
    // The connect carries an explicit local BindSpec so the DUT's source
    // port is the spec-pinned kBasicsActiveLocalPort+offset the SCXML
    // guard matches on (standard CREATE_AND_BIND + CONNECT); without the
    // bind the DUT would source an ephemeral port and the guard's
    // src_port conjunct would never fire.
    //
    // The tester listener is armed BEFORE the connect — the DUT's SYN
    // may follow by single-digit milliseconds, so a listener that lands
    // after it would race-lose to a tester-kernel RST and the
    // spec-assertion edge would never fire. The listener is harness
    // infrastructure, not DUT control, so it stays on the tester side.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce;
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // BASICS_06 requires the DUT's TCP data plane (kCapTcpControl). Both
        // shipped backends (opcode UT, AUTOSAR testability) expose it; a future
        // backend that does not must be conditioning-skipped by the centralised
        // capability gate (Tier 2 2b#4) BEFORE stimulus runs — a per-case
        // silent return here would mis-report as a timeout FAIL, not a SKIP.
        // The deref is therefore contract-guaranteed; the assert documents it.
        ITcpControl* tcp = dut.tcpControl();
        assert(tcp != nullptr && "TCP_BASICS_06 requires kCapTcpControl");

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpBasics06LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpBasics06LocalOffset;

        // RAII tester listener up before the DUT connects; the DUT's SYN
        // is on the wire by the time connectTcp returns, so the SCXML
        // arms its listen window with the spec-asserted edge already in
        // pcap's kernel buffer.
        TesterTcpListener listener(remote_port);
        const auto conn = tcp->connectTcp(
            Endpoint{cfg.ipv4.tester_ip, remote_port},
            BindSpec{/*do_bind=*/true, local_port, /*local_addr_be=*/0});

        // Give the handshake a beat to settle into the pcap ring before
        // start() arms the deadline — matches the opcode-direct prelude's
        // kTcpActiveHandshakeGrace.
        std::this_thread::sleep_for(kTcpActiveHandshakeGrace);

        if (conn) {
            tcp->closeTcp(conn->socket);
        }
        (void)listener;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_syn_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics06SM, tcp_basics_06)
