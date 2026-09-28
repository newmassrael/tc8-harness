#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_05_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing05SM =
    ::SCE::Generated::tcp_flags_processing_05::tcp_flags_processing_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing05SM>
    : TcpDutDrivenBase<cases::TcpFlagsProcessing05SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_05";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-RCVD MUST go to LISTEN state on receiving SYN "
        "(or SYN+ACK) in window (RFC 1122 §4.2.2.20(e) p94). 2 spec "
        "iterations exercise stp ∈ {SYN in window, SYN+ACK in window}";

    // Phase 1 SYN-in-window prelude is the SCXML's initial state,
    // runs sync. Phase 2 SYN+ACK-in-window is deferred via
    // scheduleAfterStateEntry on Listening_p2_prelude_synack
    // (multi-phase wall-time absence pattern).
    //
    // Each phase:
    //   1. seam passive open (driveSeamListen, listen-only) on listen_port.
    //   2. the DUT's SYN+ACK to tester_prelude_port observed on the
    //      case's own capture (awaited in phase 1, reacted to in phase 2).
    //   3. TesterAutoRstDrop alive throughout (otherwise tester
    //      kernel auto-RSTs the DUT SYN+ACK landing on the unbound
    //      tester source port and the SYN-RCVD socket dies before
    //      the spec inject lands).
    //   4. Tester SYN at seq = kTesterInitialSeq → DUT SYN+ACK
    //      observed → ISN_d.
    //   5. Spec-prescribed inject:
    //        Phase 1: SYN with seq = ISN_t + 1 (in-window past
    //                 SYN consumption).
    //        Phase 2: SYN+ACK with seq = ISN_t + 1, ack = ISN_d
    //                 + 1 (acceptable third-leg ack).
    //   6. Verify-SYN from a DIFFERENT tester source port. DUT
    //      LISTEN routes to fresh req_sock → DUT SYN+ACK on
    //      (listen_port, verify_tester_port) → SCXML transitions
    //      to next phase / pass.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        runPhase1SynInWindow(cfg, ctx.iface, ctx.dut, ctx.observer);

        std::string              iface_copy(ctx.iface);
        ::tc8::TestConfig        cfg_copy = cfg;
        // ctx.dut and ctx.scheduler outlive the poll loop (CLI- and runner-owned),
        // so capturing their addresses for the deferred phase 2 is lifetime-safe
        // (FLAGS_PROCESSING_09 idiom).
        ::tc8::sce::IDutControl*        dut_ptr   = &ctx.dut;
        ::tc8::sce::IStimulusScheduler* sched_ptr = &ctx.scheduler;

        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_prelude_synack),
            [iface_copy, cfg_copy, dut_ptr, sched_ptr]() {
                runPhase2SynAckInWindow(cfg_copy, iface_copy, *dut_ptr, *sched_ptr);
            });
    }

private:
    static void emitTesterSyn(const ::tc8::TestConfig& cfg,
                              std::string_view iface,
                              std::uint16_t src_port,
                              std::uint16_t dst_port,
                              std::uint32_t seq_value) {
        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = src_port;
        syn.dst_port = dst_port;
        syn.seq_num  = seq_value;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, syn,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void emitTesterSynAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 std::uint16_t src_port,
                                 std::uint16_t dst_port,
                                 std::uint32_t seq_value,
                                 std::uint32_t ack_value) {
        ::tc8::stimulus::TcpSegmentSpec sa{};
        sa.src_port = src_port;
        sa.dst_port = dst_port;
        sa.seq_num  = seq_value;
        sa.ack_num  = ack_value;
        sa.flags    = ::tc8::stimulus::kTcpFlagSyn
                    | ::tc8::stimulus::kTcpFlagAck;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, sa,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    // Phase 1 runs in the stimulus, before the listen window: it waits for the
    // DUT's SYN+ACK on the case's own capture.
    static void runPhase1SynInWindow(const ::tc8::TestConfig& cfg,
                                     std::string_view iface,
                                     ::tc8::sce::IDutControl& dut,
                                     ::tc8::sce::IStimulusObserver& observer) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort   = kBasicsListenPort + 10U;
        constexpr std::uint16_t kPreludeTester = kBasicsTesterPort + 72U;
        constexpr std::uint16_t kVerifyTester  = kBasicsTesterPort + 73U;

        if (!driveSeamListen(dut, kListenPort)) return;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const ::tc8::sce::ObservationCursor armed = observer.mark();

        emitTesterSyn(cfg, iface, kPreludeTester, kListenPort,
                      kTesterInitialSeq);

        const auto synack = observer.awaitObservation(
            "dut_syn_ack_phase1", armed, dutSynAckTo(cfg.dut.ip, kPreludeTester),
            std::chrono::milliseconds(500));
        if (!synack.has_value()) return;

        // CASE 1: SYN in window — seq = ISN_t + 1 (= rcv_nxt of DUT
        // after SYN consumed). DUT in SYN-RCVD on (kPreludeTester,
        // kListenPort) sees this; per Linux tcp_check_req it may
        // retx SYN+ACK or refresh the req_sock. LISTEN survives.
        emitTesterSyn(cfg, iface, kPreludeTester, kListenPort,
                      kTesterInitialSeq + 1U);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Verify LISTEN survived: fresh SYN from a different tester
        // source port → fresh req_sock → DUT SYN+ACK on (kListenPort,
        // kVerifyTester).
        emitTesterSyn(cfg, iface, kVerifyTester, kListenPort,
                      kTesterInitialSeq);
    }

    // Phase 2 runs inside the listen window, from the scheduler, so it does not
    // block the capture loop: it registers a reaction to the DUT's SYN+ACK, then
    // provokes it, and the 100 ms gap before the verify SYN is a scheduled action
    // rather than a sleep. The auto-RST suppression is owned by the closures, so
    // it lasts from before the prelude SYN until the verify SYN is out, as it did
    // when this step blocked.
    static void runPhase2SynAckInWindow(const ::tc8::TestConfig& cfg,
                                        std::string_view iface,
                                        ::tc8::sce::IDutControl& dut,
                                        ::tc8::sce::IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort   = kBasicsListenPort + 11U;
        constexpr std::uint16_t kPreludeTester = kBasicsTesterPort + 74U;
        constexpr std::uint16_t kVerifyTester  = kBasicsTesterPort + 75U;

        if (!driveSeamListen(dut, kListenPort)) return;

        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);
        ::tc8::sce::IStimulusScheduler* sched_ptr = &scheduler;
        scheduler.reactToObservation(
            "dut_syn_ack_phase2", dutSynAckTo(cfg.dut.ip, kPreludeTester),
            std::chrono::milliseconds(500),
            [rst_drop, sched_ptr, cfg, iface_str = std::string(iface)](
                const ::tc8::CapturedEvent& synack) {
                // CASE 2: SYN+ACK in window — seq = ISN_t + 1, ack = ISN_d
                // + 1. Linux tcp_check_req may treat this as the third-leg
                // and complete the handshake to ESTABLISHED, OR may handle
                // as anomaly. Either way the LISTEN socket survives — the
                // verify SYN from a different source port still elicits
                // SYN+ACK.
                emitTesterSynAck(cfg, iface_str, kPreludeTester, kListenPort,
                                 kTesterInitialSeq + 1U,
                                 segmentOf(synack).seq_num + 1U);
                sched_ptr->schedule(
                    std::chrono::milliseconds(100), [rst_drop, cfg, iface_str]() {
                        emitTesterSyn(cfg, iface_str, kVerifyTester, kListenPort,
                                      kTesterInitialSeq);
                    });
            });

        emitTesterSyn(cfg, iface, kPreludeTester, kListenPort,
                      kTesterInitialSeq);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing05SM, tcp_flags_processing_05)
