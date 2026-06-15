#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_13_sm.h"

namespace tc8::sce::cases {

using TcpBasics13SM = ::SCE::Generated::tcp_basics_13::tcp_basics_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics13SM>
    : TcpAnyBase<cases::TcpBasics13SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_13";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST NOT move on to CLOSED state from TIME-WAIT state "
        "before 2*MSL time expires, where TIME-WAIT is reached "
        "through FINWAIT-2 (NEGATIVE RFC 793 §3.2 p23 Terminology)";

    // Migrated onto the Tier-2 DUT-control seam: the FIN-WAIT-2
    // TIME-WAIT prelude runs through driveSeamTimeWaitFw2 (active OPEN
    // via the seam, DUT CLOSE via closeTcp), so the case runs unchanged
    // on whichever backend --dut-control selected. The within-2*MSL
    // replay FIN and its observation stay tester-side / SCXML-driven.
    //
    // Synchronous prelude (driveSeamTimeWaitFw2):
    //   handshake → DUT close via the seam → tester kernel auto-ACK →
    //   tester shutdown(WR) FIN → DUT pure ACK → DUT TIME-WAIT.
    // Captures tester snd_nxt/rcv_nxt for the replay-FIN raw-inject.
    //
    // Phase 2 emit (within-2*MSL replay FIN) is registered as a
    // state-entry observer on Listening_replay_ack: when the SCXML
    // transitions in (driven by the deadline_tester_fin_ack guard
    // matching the post-tester-FIN DUT ACK), the runner fires the
    // closure on the same `tick()`, raw-injecting a fresh FIN onto
    // the now-extinct (kBasicsActiveRemotePort, kBasicsActiveLocalPort)
    // 4-tuple. DUT in TIME-WAIT replies pure ACK (Linux's
    // tcp_timewait_state_process re-ACKs duplicate FINs by design)
    // — observed by Listening_replay_ack → pass. Emit-on-state-
    // entry decouples the trait from the SCXML's `<send delay>`
    // values; same shape as §4.8.6.6 FLAGS_INVALID_01 phase 3.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const auto info = driveSeamTimeWaitFw2(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics13LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics13LocalOffset);
        if (!info.ok) {
            // Helper failed (acceptOne / queryTcpSeqRange). The SCXML
            // observation chain's first deadline will fire and the
            // smoke harness logs the failure as
            // fail_no_handshake_ack — same surface as a true DUT
            // regression, with the helper's stderr line surfacing
            // the local-side root cause.
            return;
        }

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         tester_seq = info.tester_seq_post_fin;
        const std::uint32_t         tester_ack = info.tester_ack_post_fin;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_replay_ack),
            [iface_copy, cfg_copy, dut_mac, tester_seq, tester_ack]() {
                ::tc8::stimulus::TcpSegmentSpec replay{};
                replay.src_port = kBasicsActiveRemotePort + kTcpBasics13LocalOffset;
                replay.dst_port = kBasicsActiveLocalPort  + kTcpBasics13LocalOffset;
                replay.seq_num  = tester_seq;
                replay.ack_num  = tester_ack;
                replay.flags    = ::tc8::stimulus::kTcpFlagFin
                                | ::tc8::stimulus::kTcpFlagAck;
                emitTcpFrame(cfg_copy, iface_copy, dut_mac, replay,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics13SM, tcp_basics_13)
