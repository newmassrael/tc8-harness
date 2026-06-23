#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_15_neg2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid15Neg2SM = ::SCE::Generated::tcp_flags_invalid_15_neg2::tcp_flags_invalid_15_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_15 phase 2 (ESTABLISHED): a conformant DUT in
// ESTABLISHED silently drops an out-of-window RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST when the OTW RST arrives, and the case
// passes only when that synthesized RST is observed. lwIP-only (kCapIngressFault). One of the
// eight per-fail-final variants graduating the multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid15Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsInvalid15Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_15_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_15 (ESTABLISHED): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to an out-of-window "
        "RST in ESTABLISHED; a conformant DUT stays silent";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsInvalid15Phase1LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsInvalid15Phase1LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec rst{};
            rst.src_port = remote_port;
            rst.dst_port = local_port;
            rst.seq_num  = seq_range->snd_nxt + kOutOfWindowSeqOffset;
            rst.ack_num  = seq_range->rcv_nxt;
            rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, rst, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid15Neg2SM, tcp_flags_invalid_15_neg2)
