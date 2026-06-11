#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_06_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions06SM = ::SCE::Generated::tcp_mss_options_06::tcp_mss_options_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions06SM>
    : TcpAnyBase<cases::TcpMssOptions06SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST receive an MSS option in a SYN segment and clamp "
        "the effective send segment size to min(advertised, DUT_MSS) "
        "(RFC 1122 §4.2.2.6 p85). Iterations: Mv=200 (smaller), "
        "Mv=2000 (larger).";

    // Drive one iteration: open passive listener, drive raw-passive
    // handshake with caller-supplied MSS option, bulk-send via UT
    // OpSendTcpDataPattern, close. The outer RstDrop scope (in
    // stimulus()) keeps tester-kernel RSTs suppressed throughout.
    static void runPhase(const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         const std::array<std::uint8_t, 6> &dut_mac,
                         std::uint8_t  open_req_id,
                         std::uint8_t  send_req_id,
                         std::uint8_t  close_req_id,
                         std::uint8_t  socket_id,
                         std::uint16_t listen_port,
                         std::uint16_t tester_src_port,
                         std::uint16_t advertised_mss) {
        using namespace ::tc8::sce::tcp;
        // RFC 793 §3.1 kind=2 (MSS) length=4 + 16-bit value (BE).
        const std::vector<std::uint8_t> syn_options{
            0x02U, 0x04U,
            static_cast<std::uint8_t>((advertised_mss >> 8) & 0xFFU),
            static_cast<std::uint8_t>(advertised_mss & 0xFFU)};

        const auto info = driveRawPassiveHandshake(
            cfg, iface, dut_mac,
            listen_port, syn_options,
            tester_src_port,
            open_req_id,
            /*query_req_id=*/0,
            socket_id);
        (void)info;

        // 4000 B > 2 × 1460 (max DUT MSS) ensures Linux always
        // segments the write into at least 2 chunks, even at iter 2's
        // 1460-byte clamp. First segment carries min(Mv, DUT_MSS).
        sendSendTcpDataPatternRequest(
            cfg, iface, dut_mac,
            send_req_id, socket_id,
            /*pattern=*/0xA5U, /*total_len=*/4000U);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        sendCloseTcpSocketRequest(cfg, iface, dut_mac, close_req_id, socket_id);
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Phase 1: Mv = 200 (< DUT MSS=1460). First DUT data segment
        // size = 200.
        runPhase(cfg, iface, cfg.dut.mac,
                 /*open_req_id=*/1, /*send_req_id=*/2, /*close_req_id=*/3,
                 /*socket_id=*/1,
                 kTcpMssOptionsListenPort06a,
                 kTcpMssOptionsTesterSrcPort06a,
                 /*advertised_mss=*/200U);

        // Phase 2: Mv = 2000 (> DUT MSS). First DUT segment clamped
        // to DUT MSS = 1460.
        runPhase(cfg, iface, cfg.dut.mac,
                 /*open_req_id=*/4, /*send_req_id=*/5, /*close_req_id=*/6,
                 /*socket_id=*/2,
                 kTcpMssOptionsListenPort06b,
                 kTcpMssOptionsTesterSrcPort06b,
                 /*advertised_mss=*/2000U);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_wrong_size_phase1:     return "fail:phase1_segment_size_not_advertised_mss_200";
            case State::Fail_wrong_size_phase2:     return "fail:phase2_segment_size_not_dut_mss_1460";
            case State::Fail_timeout_phase1:        return "fail:no_dut_data_segment_phase1_mv200";
            case State::Fail_timeout_phase2:        return "fail:no_dut_data_segment_phase2_mv2000";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions06SM, tcp_mss_options_06)
