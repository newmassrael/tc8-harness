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

#include "tcp_mss_options_10_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions10SM = ::SCE::Generated::tcp_mss_options_10::tcp_mss_options_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions10SM>
    : TcpAnyBase<cases::TcpMssOptions10SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_10";
    static constexpr std::string_view kDescription  =
        "If an MSS option is not received at connection setup, DUT "
        "MUST default send MSS to 536 bytes (RFC 1122 §4.2.2.6 p85).";

    // Drive the default-MSS scenario once: passive ACCEPT with no MSS
    // option (DUT defaults its send MSS to 536), a 1024 B SEND, grace for
    // the first segment, then close. Factored out of stimulus() so the
    // _neg reuses the exact drive (SSOT) — the data shape (pattern byte,
    // total length) and the empty-options accept live here once, matching
    // the MSS_OPTIONS_06/09 runPhase reuse pattern. The TesterAutoRstDrop
    // scope is the caller's (held across the post-handshake data window).
    static void runPhase(::tc8::sce::IDutControl& dut,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        // Empty SYN options: Linux defaults `tp->rx_opt.mss_clamp` to
        // 536 when no kind=2 MSS arrived at handshake (RFC 1122
        // §4.2.2.6). Subsequent ::send() segments cap at 536 B.
        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpMssOptionsListenPort10,
            std::vector<std::uint8_t>{},  // no MSS option
            kTcpMssOptionsTesterSrcPort10);
        if (!open.conn) return;

        // 1024 B > 536 B ensures Linux segments the write into at
        // least 2 chunks. First chunk size = mss_clamp = 536 if the
        // DUT applied the RFC 1122 default correctly.
        seamSendTcpPattern(dut, open.conn->socket, /*pattern=*/0xAAU,
                           /*total_len=*/1024U);
        // 200 ms grace for the kernel to flush the first segment to
        // the wire — pcap captures it before the SCXML deadline fires
        // and before any subsequent close torpedoes the connection.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
    }

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Outer RstDrop scope — keeps tester-kernel RSTs against the
        // orphaned 4-tuple suppressed across the post-handshake data
        // window. The seam ACCEPT also installs the rule internally;
        // iptables -A is additive, dtor symmetry preserves the outer
        // rule until our scope ends.
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        runPhase(dut, cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions10SM, tcp_mss_options_10)
