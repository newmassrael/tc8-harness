#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_01_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions01SM = ::SCE::Generated::tcp_mss_options_01::tcp_mss_options_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions01SM>
    : TcpAnyBase<cases::TcpMssOptions01SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.9";
    static constexpr std::string_view kDescription  =
        "DUT MUST handle an illegal MSS option length in a SYN segment "
        "without crashing (RFC 1122 §4.2.2.5 p85). Iterations: ilen=0 "
        "and ilen=5.";

    // Inject one malformed SYN against a fresh DUT-side passive
    // listener: open via UT, raw-inject the SYN (TesterAutoRstDrop
    // suppresses any RST the tester kernel would emit if the DUT
    // happens to reply SYN+ACK), then UT-close the listener. Used
    // sequentially for the ilen=0 / ilen=5 iterations.
    static void injectMalformedSyn(const ::tc8::TestConfig &cfg,
                                   std::string_view iface,
                                   const std::array<std::uint8_t, 6> &dut_mac,
                                   std::uint8_t open_req_id,
                                   std::uint8_t close_req_id,
                                   std::uint8_t socket_id,
                                   std::uint16_t listen_port,
                                   std::uint16_t tester_src_port,
                                   const std::vector<std::uint8_t> &options) {
        using namespace ::tc8::sce::tcp;
        sendOpenTcpSocketPassiveRequest(
            cfg, iface, dut_mac, open_req_id, listen_port);
        std::this_thread::sleep_for(kTcpUtRpcWait);

        TesterAutoRstDrop rst_drop(cfg);

        ::tc8::stimulus::TcpSegmentSpec syn_spec{};
        syn_spec.src_port = tester_src_port;
        syn_spec.dst_port = listen_port;
        syn_spec.seq_num  = kTesterInitialSeq;
        syn_spec.flags    = ::tc8::stimulus::kTcpFlagSyn;
        syn_spec.options  = options;
        emitTcpFrame(cfg, iface, dut_mac, syn_spec);

        // 100 ms gives the DUT scheduler time to dispatch the SYN
        // through tcp_v4_rcv → tcp_parse_options. If the parser is
        // going to hang or crash, it does so well within this window.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        sendCloseTcpSocketRequest(
            cfg, iface, dut_mac, close_req_id, socket_id);
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // tc8-dut's UpperTesterServer assigns socket IDs sequentially
        // from `next_tcp_socket_id_` (skipping 0); each successful
        // OpOpenTcpSocket increments. Phase A → socket 1, Phase B →
        // socket 2, Verify → socket 3. Close / query requests must
        // reference the actual ID for that phase.

        // Iteration 1: ilen = 0. Wire bytes [0x02 0x00] padded with
        // NOP×2 → 4 B. The builder's auto-pad emits NOP rather than
        // EOL, so a parser that recovers from the malformed length
        // can resume on the next byte without prematurely terminating
        // the option list.
        injectMalformedSyn(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, /*close_req_id=*/2, /*socket_id=*/1,
            kTcpMssOptionsListenPort01a,
            kTcpMssOptionsTesterSrcPort01a,
            std::vector<std::uint8_t>{0x02U, 0x00U, 0x01U, 0x01U});

        // Iteration 2: ilen = 5. Wire bytes [0x02 0x05 0xAA 0xBB 0xCC]
        // — kind=2, length=5 (three data bytes, one more than the RFC
        // 793 §3.1 MSS encoding's 2). Options vector is 5 B; builder
        // pads with NOP×3 → 8 B. Data Offset becomes 7.
        injectMalformedSyn(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/3, /*close_req_id=*/4, /*socket_id=*/2,
            kTcpMssOptionsListenPort01b,
            kTcpMssOptionsTesterSrcPort01b,
            std::vector<std::uint8_t>{0x02U, 0x05U, 0xAAU, 0xBBU, 0xCCU});

        // Verify phase: well-formed MSS=1460 SYN. If either iteration
        // crashed the DUT, the UT RPC here times out and the SCXML
        // listen window expires on no_dut_syn_ack.
        const std::vector<std::uint8_t> verify_options{
            0x02U, 0x04U, 0x05U, 0xB4U};  // MSS = 0x05B4 = 1460

        const auto info = driveRawPassiveHandshake(
            cfg, iface, cfg.arp.dut_real_mac,
            kTcpMssOptionsListenPort01v,
            verify_options,
            kTcpMssOptionsTesterSrcPort01v,
            /*open_req_id=*/5,
            /*query_req_id=*/7,
            /*socket_id=*/3);
        c.ut_established = info.ut_established;

        sendCloseTcpSocketRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/6, /*socket_id=*/3);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_not_established:   return "fail:dut_did_not_reach_established";
            case State::Fail_timeout:           return "fail:no_dut_syn_ack_within_listen_window";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions01SM, tcp_mss_options_01)
