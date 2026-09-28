#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_08_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable08SM = ::SCE::Generated::tcp_unacceptable_08::tcp_unacceptable_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable08SM>
    : TcpAnyBase<cases::TcpUnacceptable08SM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_08";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST send a RST control message after "
        "receiving a segment with an unacceptable ACK number "
        "(RFC 793 §3.4 p36 Establishing a Connection)";

    // Each phase leaves the DUT's active open in SYN-SENT (no tester listener)
    // and injects the unacceptable-ACK segment into that state. The testability
    // CONNECT SP requires the handshake to establish and so cannot hold a
    // socket in SYN-SENT, while the opcode non-blocking worker can —
    // kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. The DUT RST
    // is observed on pcap, so no state probe is required.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;

    // Case shape — two iterations,
    // both exercised:
    //   * Phase 1 — CASE 1, flag set = SYN,ACK + unacceptable ACK.
    //   * Phase 2 — CASE 2, flag set = ACK + unacceptable ACK.
    //
    // Each phase runs the same active-OPEN → SYN learn → bad inject →
    // RST observation dance on a distinct port quad and socket_id
    // (mirror of FLAGS_INVALID_05). Phase 1 fires synchronously;
    // phase 2 schedules via scheduleAfterStateEntry(Listening_p2_dut_rst)
    // so its DUT SYN does not contend with phase 1's wall-clock
    // absence.
    //
    // Phase 2 (CASE 2) was once omitted, which a 2026-05-07 audit of
    // false-positive passes flagged; it was added here. It can race
    // tc8-dut's close-path connector-thread join, and if that race
    // shows, phase 2 ends inconclusive_p2_no_dut_rst. It did not on
    // kernel 7.0.0-31: the case passes there (single-pc 2026-09-24)
    // and carries no known-fail mark.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        runPhaseSynSentRst(
            ctx.dut, ctx.observer, cfg, ctx.iface,
            /*local_port=*/static_cast<std::uint16_t>(kBasicsActiveLocalPort + kTcpUnacceptable08Phase1LocalOffset),
            /*remote_port=*/static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpUnacceptable08Phase1LocalOffset),
            /*bad_inject_flags=*/static_cast<std::uint8_t>(
                ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck));

        // Phase 2 runs in a deferred scheduler callback that outlives this
        // stimulus frame; capture the DUT control and the scheduler by pointer
        // (both live for the run, past the callback) per the deferred-lambda idiom.
        ::tc8::sce::IDutControl*        dut_ptr   = &ctx.dut;
        ::tc8::sce::IStimulusScheduler* sched_ptr = &ctx.scheduler;
        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(ctx.iface);
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_dut_rst),
            [dut_ptr, sched_ptr, cfg_copy, iface_str]() {
                using namespace ::tc8::sce::tcp;
                armPhaseSynSentRst(
                    *dut_ptr, *sched_ptr, cfg_copy, iface_str,
                    /*local_port=*/static_cast<std::uint16_t>(kBasicsActiveLocalPort + kTcpUnacceptable08Phase2LocalOffset),
                    /*remote_port=*/static_cast<std::uint16_t>(kBasicsActiveRemotePort + kTcpUnacceptable08Phase2LocalOffset),
                    /*bad_inject_flags=*/::tc8::stimulus::kTcpFlagAck);
            });
    }

private:
    // The unacceptable-ACK segment: ack = ISN_d + a large offset, acknowledging
    // bytes the DUT never sent.
    static void emitUnacceptableAck(const ::tc8::TestConfig& cfg,
                                    std::string_view iface,
                                    std::uint16_t local_port,
                                    std::uint16_t remote_port,
                                    std::uint32_t isn_d,
                                    std::uint8_t  bad_inject_flags) {
        using namespace ::tc8::sce::tcp;
        ::tc8::stimulus::TcpSegmentSpec bad{};
        bad.src_port = remote_port;
        bad.dst_port = local_port;
        bad.seq_num  = kTesterInitialSeq;
        bad.ack_num  = isn_d + kUnacceptableAckOffset;
        bad.flags    = bad_inject_flags;
        emitTcpFrame(cfg, iface, cfg.dut.mac, bad,
                     /*initial_wait=*/std::chrono::milliseconds(0));
    }

    // Phase 2, inside the listen window: registers a reaction to the DUT's SYN and
    // then provokes it, rather than blocking the capture loop for it. The
    // auto-RST suppression and the DUT connection are owned by the closures:
    // after the inject they are held through the phase gap by a scheduled
    // action, and an unmet reaction releases them when it is dropped — the two
    // points at which the blocking form of this step let them go.
    static void armPhaseSynSentRst(::tc8::sce::IDutControl& dut,
                                   ::tc8::sce::IStimulusScheduler& scheduler,
                                   const ::tc8::TestConfig& cfg,
                                   std::string_view iface,
                                   std::uint16_t local_port,
                                   std::uint16_t remote_port,
                                   std::uint8_t  bad_inject_flags) {
        using namespace ::tc8::sce::tcp;

        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);
        auto conn     = std::make_shared<HeldDutConnection>(dut);
        ::tc8::sce::IStimulusScheduler* sched_ptr = &scheduler;
        scheduler.reactToObservation(
            "dut_syn_phase2", dutSynFrom(cfg.dut.ip, local_port),
            std::chrono::milliseconds(500),
            [rst_drop, conn, sched_ptr, cfg, iface_str = std::string(iface), local_port,
             remote_port, bad_inject_flags](const ::tc8::CapturedEvent& syn) {
                emitUnacceptableAck(cfg, iface_str, local_port, remote_port,
                                    segmentOf(syn).seq_num, bad_inject_flags);
                // Close first, then lift the suppression — the order the blocking
                // form's scope exit gave — once the phase gap has passed.
                sched_ptr->schedule(kTcpPilotPhaseGap, [rst_drop, conn]() mutable {
                    conn.reset();
                    rst_drop.reset();
                });
            });

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT, the state the unacceptable-ACK segment is
        // injected into.
        conn->hold(driveSeamSynSentOpen(dut, cfg, local_port, remote_port));
    }

    // Phase 1, in the stimulus before the listen window: waits for the DUT's SYN
    // on the case's own capture.
    static void runPhaseSynSentRst(::tc8::sce::IDutControl& dut,
                                   ::tc8::sce::IStimulusObserver& observer,
                                   const ::tc8::TestConfig& cfg,
                                   std::string_view iface,
                                   std::uint16_t local_port,
                                   std::uint16_t remote_port,
                                   std::uint8_t  bad_inject_flags) {
        using namespace ::tc8::sce::tcp;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const ::tc8::sce::ObservationCursor armed = observer.mark();

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT, the state the unacceptable-ACK segment is
        // injected into.
        auto open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = observer.awaitObservation("dut_syn_phase1", armed,
                                                   dutSynFrom(cfg.dut.ip, local_port),
                                                   std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitUnacceptableAck(cfg, iface, local_port, remote_port,
                                segmentOf(syn->view()).seq_num, bad_inject_flags);
            std::this_thread::sleep_for(kTcpPilotPhaseGap);
        }

        // A graceful close is right here and the teardown is NOT this case's
        // problem, though it looked like it: measured 2026-09-25, this close was
        // answered 3.47 s after it was issued and phase 2's open timed out behind
        // it. Swapping in `abortTcp` changed nothing, because both verbs reach the
        // same `tearDownSlot`, which JOINS a worker still sitting inside connect().
        // The fix was to make `shutdown(RDWR)` on a SYN_SENT pcb actually unblock
        // that connect on the lwIP backend — the contract the shared teardown
        // already assumed. See docs/tech-debt.md TD-24.
        if (open) dut.tcpControl()->closeTcp(open->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable08SM, tcp_unacceptable_08)
