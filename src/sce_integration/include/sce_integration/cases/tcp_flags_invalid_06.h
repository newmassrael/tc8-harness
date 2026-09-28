#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_06_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid06SM = ::SCE::Generated::tcp_flags_invalid_06::tcp_flags_invalid_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid06SM>
    : TcpAnyBase<cases::TcpFlagsInvalid06SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_06";
    static constexpr std::string_view kDescription  =
        "TCP in SYN-SENT state MUST drop a segment with neither SYN "
        "nor RST flag set and remain in the same state "
        "(RFC 793 §3.9 p68 Event Processing). 2 spec iterations "
        "exercise <stp> ∈ {no data, data}";

    // Each phase leaves the DUT's active open in SYN-SENT (no tester listener)
    // and injects the bare-ACK probe into that state. The testability CONNECT
    // SP requires the handshake to establish and so cannot hold a socket in
    // SYN-SENT, while the opcode non-blocking worker can — kCapTcpSynSentOpen
    // makes the CLI capability gate honestly SKIP this case on a testability
    // backend (Tier 2 2b#4) instead of failing it. No state probe is needed:
    // the DUT SYN is observed on pcap and the verdict is the SCXML absence
    // window.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;

    static constexpr std::array<std::uint8_t, 4> kProbePayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    // Each phase: TesterAutoRstDrop scope + active-OPEN to unbound
    // tester port + ISN_d learned from the DUT's SYN on the case's own
    // capture + raw-inject ACK
    // (no SYN, no RST) with ack=ISN_d+1 (acceptable per RFC 793
    // RFC 793 §3.4 — the only value in [SND.UNA, SND.NXT] for SYN-SENT).
    // CASE 1 carries no payload; CASE 2 carries 4 bytes of data
    // exercising the spec's `<stp> = data` iteration. Linux's
    // `tcp_rcv_synsent_state_process` drops the segment without
    // emitting any response in either case (the discard fall-
    // through fires before any SYN-processing branch).
    //
    // Phase 1 fires synchronously; phase 2 schedules via
    // `scheduleAfterStateEntry(Listening_p2_dut_syn)` so its DUT
    // SYN is not queued behind phase 1's wall-clock absence. Same
    // shape as FLAGS_INVALID_05 / _15.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1BareAck(ctx.dut, ctx.observer, cfg, ctx.iface);

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
                runPhase2AckWithPayload(*dut_ptr, *sched_ptr, cfg_copy, iface_str);
            });
    }

private:
    static void emitAck(const ::tc8::TestConfig& cfg,
                        std::string_view iface,
                        std::uint16_t local_port,
                        std::uint16_t remote_port,
                        std::uint32_t isn_d,
                        std::vector<std::uint8_t> payload) {
        ::tc8::stimulus::TcpSegmentSpec probe{};
        probe.src_port = remote_port;
        probe.dst_port = local_port;
        probe.seq_num  = ::tc8::sce::tcp::kTesterInitialSeq;
        probe.ack_num  = isn_d + 1U;
        probe.flags    = ::tc8::stimulus::kTcpFlagAck;
        probe.payload  = std::move(payload);
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
    }

    // Phase 1 runs in the stimulus, before the listen window: it waits for the
    // DUT's SYN on the case's own capture, then injects the probe.
    static void runPhase1BareAck(::tc8::sce::IDutControl& dut,
                                 ::tc8::sce::IStimulusObserver& observer,
                                 const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid06Phase1LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid06Phase1LocalOffset;

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
            emitAck(cfg, iface, local_port, remote_port, segmentOf(syn->view()).seq_num, {});
        }
    }

    // Phase 2 runs inside the listen window, from the scheduler, so it does not
    // wait: it registers a reaction to the DUT's SYN and then provokes it. The
    // reaction's closure owns the auto-RST suppression, so the tester kernel stays
    // silent until the probe is injected (or the bound elapses), exactly as long
    // as it did when this step blocked for the SYN.
    static void runPhase2AckWithPayload(::tc8::sce::IDutControl& dut,
                                        ::tc8::sce::IStimulusScheduler& scheduler,
                                        const ::tc8::TestConfig& cfg,
                                        std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid06Phase2LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid06Phase2LocalOffset;

        auto rst_drop = std::make_shared<TesterAutoRstDrop>(cfg);
        scheduler.reactToObservation(
            "dut_syn_phase2", dutSynFrom(cfg.dut.ip, local_port),
            std::chrono::milliseconds(500),
            [rst_drop, cfg, iface_str = std::string(iface), local_port,
             remote_port](const ::tc8::CapturedEvent& syn) {
                emitAck(cfg, iface_str, local_port, remote_port, segmentOf(syn).seq_num,
                        std::vector<std::uint8_t>(kProbePayload.begin(),
                                                  kProbePayload.end()));
            });

        // Seam active OPEN, no tester listener: the SYN stays unanswered so the
        // DUT remains in SYN-SENT. Handle discarded (no closeTcp).
        (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid06SM, tcp_flags_invalid_06)
