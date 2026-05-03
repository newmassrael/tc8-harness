#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    : TcpAnyBase<cases::TcpFlagsProcessing05SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
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
    //   1. UT OpOpenTcpSocket(passive, listen_port).
    //   2. snippet on (tester_prelude_port → listen_port) for DUT
    //      SYN+ACK observation.
    //   3. TesterAutoRstDrop alive throughout (otherwise tester
    //      kernel auto-RSTs the DUT SYN+ACK landing on the unbound
    //      tester source port and the SYN-RCVD socket dies before
    //      the spec inject lands).
    //   4. Tester SYN at seq = kTesterInitialSeq → DUT SYN+ACK
    //      learned via snippet → ISN_d.
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
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1SynInWindow(cfg, iface);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        std::array<std::uint8_t, 6> dut_mac  = cfg.arp.dut_real_mac;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_prelude_synack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase2SynAckInWindow(cfg_copy, iface_copy);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                           return "pass";
            case State::Fail_p1_no_prelude_synack:      return "fail:no_dut_synack_to_prelude_syn_phase1";
            case State::Fail_p1_no_verify_synack:       return "fail:no_dut_synack_to_verify_syn_after_in_window_syn";
            case State::Fail_p2_no_prelude_synack:      return "fail:no_dut_synack_to_prelude_syn_phase2";
            case State::Fail_p2_no_verify_synack:       return "fail:no_dut_synack_to_verify_syn_after_in_window_synack";
            default:                                    return "running";
        }
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
            cfg, iface, cfg.arp.dut_real_mac, syn,
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
            cfg, iface, cfg.arp.dut_real_mac, sa,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1SynInWindow(const ::tc8::TestConfig& cfg,
                                     std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort   = kBasicsListenPort + 10U;
        constexpr std::uint16_t kPreludeTester = kBasicsTesterPort + 72U;
        constexpr std::uint16_t kVerifyTester  = kBasicsTesterPort + 73U;

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/1, kListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSynAck(
            cfg, iface, kPreludeTester);

        emitTesterSyn(cfg, iface, kPreludeTester, kListenPort,
                      kTesterInitialSeq);

        const auto synack = snippet.tryCapture(
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

    static void runPhase2SynAckInWindow(const ::tc8::TestConfig& cfg,
                                        std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort   = kBasicsListenPort + 11U;
        constexpr std::uint16_t kPreludeTester = kBasicsTesterPort + 74U;
        constexpr std::uint16_t kVerifyTester  = kBasicsTesterPort + 75U;

        sendOpenTcpSocketPassiveRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/3, kListenPort);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        auto snippet = TcpFrameSnippet::forDutSynAck(
            cfg, iface, kPreludeTester);

        emitTesterSyn(cfg, iface, kPreludeTester, kListenPort,
                      kTesterInitialSeq);

        const auto synack = snippet.tryCapture(
            std::chrono::milliseconds(500));
        if (!synack.has_value()) return;

        // CASE 2: SYN+ACK in window — seq = ISN_t + 1, ack = ISN_d
        // + 1. Linux tcp_check_req may treat this as the third-leg
        // and complete the handshake to ESTABLISHED, OR may handle
        // as anomaly. Either way the LISTEN socket survives — the
        // verify SYN from a different source port still elicits
        // SYN+ACK.
        emitTesterSynAck(cfg, iface, kPreludeTester, kListenPort,
                         kTesterInitialSeq + 1U,
                         synack->seq_num + 1U);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        emitTesterSyn(cfg, iface, kVerifyTester, kListenPort,
                      kTesterInitialSeq);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing05SM, tcp_flags_processing_05)
