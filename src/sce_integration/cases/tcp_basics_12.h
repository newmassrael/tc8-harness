#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_12_sm.h"

namespace tc8::sce::cases {

using TcpBasics12SM = ::SCE::Generated::tcp_basics_12::tcp_basics_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics12SM>
    : TcpAnyBase<cases::TcpBasics12SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_12";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST move on to CLOSED state from TIME-WAIT state after "
        "a timeout of 2*MSL, where TIME-WAIT is reached through "
        "CLOSING (RFC 793 §3.2 p23 Terminology)";

    // CLOSING-path prelude (driveSeamCloseToTimeWaitClosing) walks DUT
    // through ESTABLISHED → FIN-WAIT-1 → CLOSING → TIME-WAIT. The
    // post-2*MSL FIN-replay schedules through scheduleAfterStateEntry
    // chained with schedule(kTimeWaitFullWait, …) — same
    // wall-time-decoupled pattern as BASICS_11 but with the prelude
    // exercising the CLOSING entry path instead of FIN-WAIT-2.
    // Migrated onto the Tier-2 DUT-control seam: the CLOSING-path TIME-WAIT
    // prelude runs through `driveSeamActiveOpen` (active OPEN) +
    // `driveSeamCloseToTimeWaitClosing` (DUT CLOSE via closeTcp), so the case
    // runs unchanged on whichever backend `--dut-control` selected. The
    // tester-side FIN/ACK raw inject and the post-2*MSL replay stay case-owned.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpBasics12LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics12LocalOffset);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        const auto info = driveSeamCloseToTimeWaitClosing(
            dut, cfg, iface, tester_fd, open.conn->socket,
            kBasicsActiveLocalPort  + kTcpBasics12LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics12LocalOffset);
        if (!info.ok) return;

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         tester_seq = info.tester_seq_post_fin;
        const std::uint32_t         tester_ack = info.tester_ack_post_fin;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_replay_rst),
            [&scheduler, iface_copy, cfg_copy, dut_mac,
             tester_seq, tester_ack]() {
                scheduler.schedule(
                    kTimeWaitFullWait,
                    [iface_copy, cfg_copy, dut_mac,
                     tester_seq, tester_ack]() {
                        ::tc8::stimulus::TcpSegmentSpec replay{};
                        replay.src_port = kBasicsActiveRemotePort + kTcpBasics12LocalOffset;
                        replay.dst_port = kBasicsActiveLocalPort  + kTcpBasics12LocalOffset;
                        replay.seq_num  = tester_seq;
                        replay.ack_num  = tester_ack;
                        replay.flags    = ::tc8::stimulus::kTcpFlagFin
                                        | ::tc8::stimulus::kTcpFlagAck;
                        emitTcpFrame(cfg_copy, iface_copy, dut_mac, replay,
                                     /*initial_wait=*/std::chrono::milliseconds(0));
                    });
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics12SM, tcp_basics_12)
