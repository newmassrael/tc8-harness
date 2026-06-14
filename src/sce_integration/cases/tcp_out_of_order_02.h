#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_out_of_order_02_sm.h"

namespace tc8::sce::cases {

using TcpOutOfOrder02SM =
    ::SCE::Generated::tcp_out_of_order_02::tcp_out_of_order_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpOutOfOrder02SM>
    : TcpAnyBase<cases::TcpOutOfOrder02SM> {
    static constexpr std::string_view kCaseId       = "TCP_OUT_OF_ORDER_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.10";
    static constexpr std::string_view kDescription  =
        "DUT TCP delayed-ACK MUST fire within 0.5 sec — cumulative "
        "ACK covering two consecutive data segments arrives in time "
        "(RFC 1122 §4.2.3.2 p96 SHOULD/MUST).";

    // Two 100-byte segments — well below MSS so the spec's
    // "consecutively without any delay" intent stays clean at the
    // wire layer (no inter-segment pacing needed) and large enough
    // to exercise the cumulative-ACK code path. Distinct first byte
    // ('A'/'B') keeps the segments visually identifiable in pcap;
    // exact bytes are not load-bearing — only count and SEQ ranges
    // matter.
    static constexpr std::uint16_t kSegPayloadLen = 100U;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpOutOfOrder02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpOutOfOrder02LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;
        // Cumulative ack covers BOTH segments after the second arrives.
        c.expected_ack_num = injected_seq +
            static_cast<std::uint32_t>(2U * kSegPayloadLen);

        const auto build_seg = [&](std::uint32_t seq, std::uint8_t fill) {
            ::tc8::stimulus::TcpSegmentSpec spec{};
            spec.src_port = remote_port;
            spec.dst_port = local_port;
            spec.seq_num  = seq;
            spec.ack_num  = seq_range->rcv_nxt;
            spec.flags    = ::tc8::stimulus::kTcpFlagAck
                          | ::tc8::stimulus::kTcpFlagPsh;
            spec.payload.assign(kSegPayloadLen, fill);
            return spec;
        };

        // No inter-segment pacing — spec's "consecutively without any
        // delay" intent. Both segments hit the kernel back-to-back so
        // the delayed-ACK timer sees both before firing.
        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq, std::uint8_t{'A'}),
                     /*initial_wait=*/std::chrono::milliseconds(0));
        emitTcpFrame(cfg, iface, cfg.dut.mac,
                     build_seg(injected_seq + kSegPayloadLen,
                               std::uint8_t{'B'}),
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                       return "pass";
            case State::Fail_no_handshake_ack:                      return "fail:no_dut_handshake_ack";
            case State::Fail_no_cumulative_ack_within_500ms:        return "fail:dut_did_not_emit_cumulative_ack_for_two_segments_within_500ms";
            default:                                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpOutOfOrder02SM, tcp_out_of_order_02)
