#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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

    // Drive one iteration: seam raw-passive ACCEPT with caller-supplied
    // MSS option, bulk-send via the seam sendTcpPattern, close. The outer
    // RstDrop scope (in stimulus()) keeps tester-kernel RSTs suppressed
    // throughout. Backend-agnostic — runs on opcode or testability.
    static void runPhase(::tc8::sce::IDutControl& dut,
                         const ::tc8::TestConfig &cfg,
                         std::string_view iface,
                         std::uint16_t listen_port,
                         std::uint16_t tester_src_port,
                         std::uint16_t advertised_mss) {
        using namespace ::tc8::sce::tcp;
        // RFC 793 §3.1 kind=2 (MSS) length=4 + 16-bit value (BE).
        const std::vector<std::uint8_t> syn_options{
            0x02U, 0x04U,
            static_cast<std::uint8_t>((advertised_mss >> 8) & 0xFFU),
            static_cast<std::uint8_t>(advertised_mss & 0xFFU)};

        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface, listen_port, syn_options, tester_src_port);
        if (!open.conn) return;

        // 4000 B > 2 × 1460 (max DUT MSS) ensures Linux always
        // segments the write into at least 2 chunks, even at iter 2's
        // 1460-byte clamp. First segment carries min(Mv, DUT_MSS).
        seamSendTcpPattern(dut, open.conn->socket, /*pattern=*/0xA5U,
                           /*total_len=*/4000U);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        std::this_thread::sleep_for(kTcpUtRpcWait);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Phase 1: Mv = 200 (< DUT MSS=1460). First DUT data segment
        // size = 200.
        runPhase(dut, cfg, iface,
                 kTcpMssOptionsListenPort06a,
                 kTcpMssOptionsTesterSrcPort06a,
                 /*advertised_mss=*/200U);

        // Phase 2: Mv = 2000 (> DUT MSS). First DUT segment clamped
        // to DUT MSS = 1460.
        runPhase(dut, cfg, iface,
                 kTcpMssOptionsListenPort06b,
                 kTcpMssOptionsTesterSrcPort06b,
                 /*advertised_mss=*/2000U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions06SM, tcp_mss_options_06)
