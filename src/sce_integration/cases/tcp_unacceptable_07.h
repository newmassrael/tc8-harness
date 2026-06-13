#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_07_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable07SM = ::SCE::Generated::tcp_unacceptable_07::tcp_unacceptable_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable07SM>
    : TcpAnyBase<cases::TcpUnacceptable07SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.3";
    static constexpr std::string_view kDescription  =
        "TCP in LISTEN state MUST send a RST after receiving a spurious "
        "SYN,ACK (RFC 793 §3.4 p35 Establishing a Connection)";

    // Spec Test Procedure (v3.0 p301-p320.txt:473):
    //   1. TESTER: Cause DUT to move to LISTEN.
    //   2. TESTER: Send a SYN,ACK.
    //   3. DUT:    Send a RST.
    //
    // The tester injects a single SYN+ACK at a passive listener; the
    // DUT in LISTEN never had a prior SYN-SENT context, so RFC 793
    // RFC 793 §3.4 p35 mandates an RST response. Linux fills this path via
    // `tcp_v4_send_reset` whose SEQ derives from the incoming ACK.
    // The arbitrary `kTesterInitialSeq + 1` ack value avoids landing
    // on 0 (which a buggy emit-any-RST might use as a default) so
    // the wire-level SEQ inheritance is observable.
    //
    // Migrated onto the Tier-2 DUT-control seam: the LISTEN is established
    // through `driveSeamListen` (ITcpControl::listenTcp, listen-only — the
    // handshake never completes so there is no accept to confirm) and torn down
    // through `closeTcp`, so the case runs on whichever backend `--dut-control`
    // selected. The SYN+ACK inject and the RST observation are tester-side
    // (raw-inject + SCXML gate), unchanged.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) return;

        ::tc8::stimulus::TcpSegmentSpec synack{};
        synack.src_port = kBasicsTesterPort;
        synack.dst_port = kBasicsListenPort;
        synack.seq_num  = kTesterInitialSeq;
        synack.ack_num  = kTesterInitialSeq + 1U;
        synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                        | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, synack);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:           return "pass";
            case State::Fail_timeout:   return "fail:no_dut_rst_to_listen_synack";
            default:                    return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable07SM, tcp_unacceptable_07)
