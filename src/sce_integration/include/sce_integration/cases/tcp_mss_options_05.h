#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_call_intent.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/dut_liveness.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_mss_options_05_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions05SM = ::SCE::Generated::tcp_mss_options_05::tcp_mss_options_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions05SM>
    : TcpAnyBase<cases::TcpMssOptions05SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_05";
    static constexpr std::string_view kDescription  =
        "TCP MUST handle an illegal MSS option length in a SYN,ACK "
        "segment without crashing (RFC 1122 §4.2.2.5 p85). Iterations: "
        "ilen=0 and ilen=5.";

    // Each iteration holds the DUT's active open in SYN-SENT (no tester
    // listener) until the crafted SYN+ACK injection establishes it. The
    // testability CONNECT SP requires the handshake to establish and so cannot
    // hold a socket in SYN-SENT, while the opcode non-blocking worker can —
    // kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. Whether
    // the DUT survived is graded by the liveness probe (dut_liveness.h), not
    // by a state query, which a crashed DUT could not answer.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    // The case's segments and the Echo Reply to its liveness probe.
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::TcpAndIcmpv4;

    // Drive one iteration of the spec procedure: active OPEN, capture
    // DUT SYN, raw-inject SYN+ACK carrying `bad_options` bytes, give the
    // DUT time to process it, close the socket.
    // The TesterAutoRstDrop scope spans the SYN-SENT period only —
    // after the DUT reaches ESTABLISHED via our injection, dropping
    // RST is no longer needed, and tearing the rule down before UT
    // close lets the tester kernel cleanly RST the orphaned 4-tuple
    // when tc8-dut emits FIN.
    static void runPhase(::tc8::sce::IDutControl& dut,
                         const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         ::tc8::sce::IStimulusObserver& observer,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         std::uint16_t port_offset,
                         const std::vector<std::uint8_t> &bad_options) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  =
            static_cast<std::uint16_t>(kBasicsActiveLocalPort  + port_offset);
        const std::uint16_t remote_port =
            static_cast<std::uint16_t>(kBasicsActiveRemotePort + port_offset);

        const ::tc8::sce::ObservationCursor armed = observer.mark();

        std::optional<::tc8::sce::DutConnection> open;
        {
            TesterAutoRstDrop rst_drop(cfg);
            (void)rst_drop;

            // Seam active OPEN, no tester listener: the SYN stays unanswered so
            // the DUT remains in SYN-SENT until the SYN+ACK injection below.
            open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

            const auto syn = observer.awaitObservation(
                "dut_syn", armed, dutSynFrom(cfg.dut.ip, local_port),
                std::chrono::milliseconds(1000));
            if (syn.has_value()) {
                ::tc8::stimulus::TcpSegmentSpec synack{};
                synack.src_port = remote_port;
                synack.dst_port = local_port;
                synack.seq_num  = kTesterInitialSeq;
                synack.ack_num  = segmentOf(syn->view()).seq_num + 1U;
                synack.flags    = ::tc8::stimulus::kTcpFlagSyn
                                | ::tc8::stimulus::kTcpFlagAck;
                synack.options  = bad_options;
                emitTcpFrame(cfg, iface, dut_mac, synack,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            }

            // 200 ms grace for the DUT TCB to process the SYN+ACK
            // (its answer, if any, is in the pcap; it is not graded).
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        if (open) {
            // Releasing the connection bears on no verdict; the liveness probe
            // after this phase is what grades whether the DUT survived.
            const ::tc8::sce::DutCallIntentScope cleanup(::tc8::sce::DutCallIntent::kCleanup);
            dut.tcpControl()->closeTcp(open->socket);
        }
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        c.liveness_dut_ip = cfg.dut.ip;

        // Iteration 1: ilen=0 (less than RFC 793 §3.1 MSS opsize=4).
        // Wire bytes [0x02 0x00] padded with NOP×2 → 4 B. Linux's
        // `tcp_parse_options` aborts further option parsing at
        // `opsize < 2` and proceeds with the rest of the SYN+ACK.
        runPhase(ctx.dut, cfg, ctx.iface, ctx.observer, cfg.dut.mac,
                 kTcpMssOptions05Phase1LocalOffset,
                 std::vector<std::uint8_t>{0x02U, 0x00U, 0x01U, 0x01U});
        const std::chrono::milliseconds listen(cfg.ixit.param_listen_time_ms);
        if (!::tc8::sce::liveness::probeLiveness(cfg, ctx.iface, ctx.observer, 1, listen)) return;

        // Iteration 2: ilen=5 (more than actual). Wire bytes
        // [0x02 0x05 0xAA 0xBB 0xCC] — kind=2, length=5 (3 data
        // bytes, one more than the RFC encoding's 2). Builder pads
        // with NOP×3 → 8 B options region; Data Offset = 7. Linux
        // skips the option per `opsize > TCPOLEN_MSS` and continues.
        runPhase(ctx.dut, cfg, ctx.iface, ctx.observer, cfg.dut.mac,
                 kTcpMssOptions05Phase2LocalOffset,
                 std::vector<std::uint8_t>{0x02U, 0x05U, 0xAAU, 0xBBU, 0xCCU});
        ::tc8::sce::liveness::probeLiveness(cfg, ctx.iface, ctx.observer, 2, listen);
    }

    // The case grades only the DUT's answers to its liveness probes; its own TCP
    // segments are recorded in the pcap and bear on no transition.
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const std::uint16_t seq = ::tc8::sce::liveness::livenessEchoReplySeq(ev, c.liveness_dut_ip);
        if (seq == 0U) return;
        c.liveness_echo_seq = seq;
        sm.raiseExternal(Event::Dut_echo_reply);
        sm.step();
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions05SM, tcp_mss_options_05)
