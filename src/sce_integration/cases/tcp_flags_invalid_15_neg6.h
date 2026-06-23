#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_15_neg6_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid15Neg6SM = ::SCE::Generated::tcp_flags_invalid_15_neg6::tcp_flags_invalid_15_neg6;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_15 phase 6 (CLOSING): a conformant DUT in
// CLOSING silently drops an out-of-window RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the
// lwIP netif input hook synthesize the prohibited RST when the OTW RST arrives, and the case
// passes only when that synthesized RST is observed. lwIP-only (kCapIngressFault). One of the
// eight per-fail-final variants graduating the multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid15Neg6SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid15Neg6SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_15_NEG6";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_15 (CLOSING): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to an out-of-window "
        "RST in CLOSING; a conformant DUT stays silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid15Phase5LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid15Phase5LocalOffset;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        const auto info = driveSeamCloseToClosing(
            dut, cfg, iface, tester_fd, open.conn->socket, local_port, remote_port);
        if (info.ok) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec rst{};
            rst.src_port = remote_port;
            rst.dst_port = local_port;
            rst.seq_num  = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
            rst.ack_num  = info.tester_ack_post_fin - 1U;
            rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid15Neg6SM, tcp_flags_invalid_15_neg6)
