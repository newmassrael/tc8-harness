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

#include "tcp_control_flags_05_sm.h"

namespace tc8::sce::cases {

using TcpControlFlags05SM =
    ::SCE::Generated::tcp_control_flags_05::tcp_control_flags_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpControlFlags05SM>
    : TcpAnyBase<cases::TcpControlFlags05SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONTROL_FLAGS_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.19";
    static constexpr std::string_view kDescription  =
        "DUT receives a TCP packet with the URG flag set and replies "
        "with an ACK whose ack_num is the expected value (RFC 4413 "
        "§4.2.4).";

    static constexpr std::array<std::uint8_t, 4> kUrgPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpControlFlags05LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpControlFlags05LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kUrgPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        ::tc8::stimulus::TcpSegmentSpec urg_seg{};
        urg_seg.src_port       = remote_port;
        urg_seg.dst_port       = local_port;
        urg_seg.seq_num        = injected_seq;
        urg_seg.ack_num        = seq_range->rcv_nxt;
        urg_seg.flags          = ::tc8::stimulus::kTcpFlagUrg
                               | ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
        // RFC 793 §3.1 / RFC 1122 §4.2.2.4 BSD interpretation: urgent
        // pointer = offset (1-based) of the LAST urgent byte within the
        // segment payload. Setting it to payload_len means "the entire
        // payload is urgent data" — a structurally distinct value from
        // 0 (no urgent data despite URG bit) or > payload_len (out-of-
        // segment, RFC 6093 §3 cautions).
        urg_seg.urgent_pointer =
            static_cast<std::uint16_t>(kUrgPayload.size());
        urg_seg.payload.assign(kUrgPayload.begin(), kUrgPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, urg_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_urg_ack:            return "fail:no_dut_ack_to_urg_segment";
            case State::Fail_wrong_ack_num:         return "fail:dut_ack_num_does_not_acknowledge_urg_payload";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpControlFlags05SM, tcp_control_flags_05)
