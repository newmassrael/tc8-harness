#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_10_neg_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions10NegSM = ::SCE::Generated::tcp_mss_options_10_neg::tcp_mss_options_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.9 TCP_MSS_OPTIONS_10: with no MSS option at setup, a conformant DUT
// defaults its send MSS to 536 and segments a SEND at 536 B (RFC 1122 §4.2.2.6). kTcpFaultDataSegTruncate
// shrinks the DUT data segment's IP total_length so libtins re-slices the dissected payload to 64 B,
// so the dut_data_segment_size_not_default_536 fail-final (payload_len != 536) is reachable; the case
// passes only when that truncated segment is observed. lwIP-only (kCapEgressFault). Single fail-final,
// so no coverage.json entry.
template <>
struct TestCaseTraits<cases::TcpMssOptions10NegSM>
    : TcpEgressFaultNegBase<cases::TcpMssOptions10NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_10_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_10: the lwIP kTcpFaultDataSegTruncate egress flavor "
        "shrinks the DUT data segment below 536 B; a conformant DUT segments at the 536 default";

    // Arm the data-segment truncate, then drive the same passive ACCEPT (no MSS option) + 1024 B
    // SEND the positive uses. The flavor is payload-gated, so the handshake's control segments are
    // untouched and the connection reaches the data-emitting state; the DUT's 536 B data segment is
    // emitted with a shrunk IP total_length, so the dissected payload_len drops to 64 (!= 536).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultDataSegTruncate);

        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpMssOptionsListenPort10,
            std::vector<std::uint8_t>{},  // no MSS option -> DUT default send MSS 536
            kTcpMssOptionsTesterSrcPort10);
        if (!open.conn) return;

        seamSendTcpPattern(dut, open.conn->socket, /*pattern=*/0xAAU, /*total_len=*/1024U);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions10NegSM, tcp_mss_options_10_neg)
