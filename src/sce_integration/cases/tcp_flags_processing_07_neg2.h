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

#include "tcp_flags_processing_07_neg2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing07Neg2SM =
    ::SCE::Generated::tcp_flags_processing_07_neg2::tcp_flags_processing_07_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_07 phase 2 (CLOSING): a conformant DUT in
// CLOSING silently ignores a URG-only segment (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST on the connection's 4-tuple when the
// URG-only segment arrives, and the case passes only when that synthesized RST is observed.
// lwIP-only (kCapIngressFault). One of the four per-fail-final variants graduating the
// multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing07Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing07Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_07_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_07 (CLOSING): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to a URG-only segment "
        "in CLOSING; a conformant DUT stays silent";

    // Mirrors the positive's phase-2 seam (active OPEN + driveSeamCloseToClosing -> DUT
    // CLOSING), with the fault armed AFTER the close handshake's FINs and BEFORE the URG inject.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 54U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 54U;

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
            ::tc8::stimulus::TcpSegmentSpec urg{};
            urg.src_port = remote_port;
            urg.dst_port = local_port;
            urg.seq_num  = info.tester_seq_post_fin;
            urg.ack_num  = 0U;
            urg.flags    = ::tc8::stimulus::kTcpFlagUrg;
            emitTcpFrame(cfg, iface, cfg.dut.mac, urg, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing07Neg2SM, tcp_flags_processing_07_neg2)
