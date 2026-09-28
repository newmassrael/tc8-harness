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

#include "tcp_flags_invalid_05_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05SM = ::SCE::Generated::tcp_flags_invalid_05::tcp_flags_invalid_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05SM>
    : TcpAnyBase<cases::TcpFlagsInvalid05SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_05";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST move on to CLOSED state after "
        "receiving a segment with ACK and RST and acceptable ACK "
        "number (RFC 793 §3.9 p67 Event Processing). 2 spec "
        "iterations exercise flag set ∈ {SYN+ACK, ACK} alongside RST";

    // Each phase leaves the DUT's active open in SYN-SENT (no tester listener)
    // and injects the RST-bearing probe into that state. The testability CONNECT
    // SP requires the handshake to establish and so cannot hold a socket in
    // SYN-SENT, while the opcode non-blocking worker can — kCapTcpSynSentOpen
    // makes the CLI capability gate honestly SKIP this case on a testability
    // backend (Tier 2 2b#4) instead of failing it. No state probe is needed:
    // the DUT SYN is observed on pcap and the verdict is the SCXML absence
    // window.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;

    // Each phase: TesterAutoRstDrop scope + active-OPEN to unbound
    // tester port + ISN_d learned from the DUT's SYN on the case's own
    // capture + raw-inject RST with
    // ack=ISN_d+1 (acceptable, the only value in [SND.UNA, SND.NXT]
    // for SYN-SENT). CASE 1's probe carries SYN+ACK+RST; CASE 2's
    // carries ACK+RST. Linux's `tcp_rcv_synsent_state_process`
    // accepts the ACK then enters the RST branch and calls
    // `tcp_done(sk)` which transitions the socket to CLOSED and
    // cancels the SYN retransmit timer — observable on the wire as
    // absence of further DUT SYN retransmits in the 3 s window.
    //
    // Phase 1 fires synchronously; phase 2 schedules via
    // `scheduleAfterStateEntry(Listening_p2_dut_syn)` so its DUT SYN
    // is not queued behind phase 1's wall-clock absence. Same shape
    // as FLAGS_INVALID_15 phases 2..8.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;

        runPhase1SynAckRst(ctx.dut, ctx.observer, cfg, ctx.iface);

        // Phase 2 runs in a deferred scheduler callback that outlives this
        // stimulus frame; capture the DUT control and the scheduler by pointer
        // (both live for the run, past the callback) per the deferred-lambda idiom.
        ::tc8::sce::IDutControl*        dut_ptr   = &ctx.dut;
        ::tc8::sce::IStimulusScheduler* sched_ptr = &ctx.scheduler;
        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(ctx.iface);
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_dut_syn),
            [dut_ptr, sched_ptr, cfg_copy, iface_str]() {
                runPhase2AckRst(*dut_ptr, *sched_ptr, cfg_copy, iface_str);
            });
    }

private:
    static void emitRstWithFlags(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 std::uint16_t local_port,
                                 std::uint16_t remote_port,
                                 std::uint32_t isn_d,
                                 std::uint8_t  flags) {
        ::tc8::stimulus::TcpSegmentSpec probe{};
        probe.src_port = remote_port;
        probe.dst_port = local_port;
        probe.seq_num  = ::tc8::sce::tcp::kTesterInitialSeq;
        probe.ack_num  = isn_d + 1U;
        probe.flags    = flags;
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
    }

    // Phase 1 runs in the stimulus, before the listen window: it waits for the
    // DUT's SYN on the case's own capture, then injects the probe.
    static void runPhase1SynAckRst(::tc8::sce::IDutControl& dut,
                                   ::tc8::sce::IStimulusObserver& observer,
                                   const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid05Phase1LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid05Phase1LocalOffset;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const ::tc8::sce::ObservationCursor armed = observer.mark();

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT. Handle discarded (no closeTcp).
        (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = observer.awaitObservation(
            "dut_syn_phase1", armed, dutSynFrom(cfg.dut.ip, local_port),
            std::chrono::milliseconds(500));
        if (syn.has_value()) {
            emitRstWithFlags(cfg, iface, local_port, remote_port,
                             segmentOf(syn->view()).seq_num,
                             ::tc8::stimulus::kTcpFlagSyn
                                 | ::tc8::stimulus::kTcpFlagAck
                                 | ::tc8::stimulus::kTcpFlagRst);
        }
    }

    // Phase 2 runs inside the listen window, from the scheduler, so it does not
    // wait: it registers a reaction to the DUT's SYN and then provokes it. The
    // reaction's closure owns the auto-RST suppression, so the tester kernel stays
    // silent until the probe is injected (or the bound elapses), exactly as long
    // as it did when this step blocked for the SYN.
    static void runPhase2AckRst(::tc8::sce::IDutControl& dut,
                                ::tc8::sce::IStimulusScheduler& scheduler,
                                const ::tc8::TestConfig& cfg,
                                std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid05Phase2LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid05Phase2LocalOffset;

        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);
        scheduler.reactToObservation(
            "dut_syn_phase2", dutSynFrom(cfg.dut.ip, local_port),
            std::chrono::milliseconds(500),
            [rst_drop, cfg, iface_str = std::string(iface), local_port,
             remote_port](const ::tc8::CapturedEvent& syn) {
                emitRstWithFlags(cfg, iface_str, local_port, remote_port,
                                 segmentOf(syn).seq_num,
                                 ::tc8::stimulus::kTcpFlagAck
                                     | ::tc8::stimulus::kTcpFlagRst);
            });

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT. Handle discarded (no closeTcp).
        (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05SM, tcp_flags_invalid_05)
