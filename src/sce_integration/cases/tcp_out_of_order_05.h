#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_out_of_order_05_sm.h"

namespace tc8::sce::cases {

using TcpOutOfOrder05SM =
    ::SCE::Generated::tcp_out_of_order_05::tcp_out_of_order_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpOutOfOrder05SM>
    : TcpAnyBase<cases::TcpOutOfOrder05SM> {
    static constexpr std::string_view kCaseId       = "TCP_OUT_OF_ORDER_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.10";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST emit at least one ACK per two full-sized "
        "segments in a stream (RFC 1122 §4.2.3.2 p96 stretchACK floor).";

    // Full-sized segment per RFC 879 / RFC 1122 §4.2.2.6 = MSS bytes.
    // veth's default MTU 1500 admits IP 20 + TCP 20 + payload 1460 =
    // 1500.
    static constexpr std::uint16_t kFullSizedPayloadLen = 1460U;

    // Burst depth — N=10 keeps total bytes (14600) well under the
    // default Linux receive buffer (87380 B initial + auto-tune) so
    // no segments are dropped for receive-window exhaustion. The
    // SCXML's 5-ACK consume chain asserts "≥ N/2 ACKs" against the
    // every-other-segment stretchACK floor.
    static constexpr std::uint16_t kBurstSegmentCount = 10U;

    // 5 ms inter-segment pacing keeps each kernel ACK on the wire
    // in arrival order without pcap dispatch coalescing them into a
    // single snapshot. Same idiom as OUT_OF_ORDER_03's 4-segment
    // burst; consistent treatment of multi-segment raw-inject.
    static constexpr std::chrono::milliseconds kInterSegmentWait{5};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpOutOfOrder05LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpOutOfOrder05LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;

        const auto build_seg = [&](std::uint32_t seq, std::uint8_t fill) {
            ::tc8::stimulus::TcpSegmentSpec spec{};
            spec.src_port = remote_port;
            spec.dst_port = local_port;
            spec.seq_num  = seq;
            spec.ack_num  = seq_range->rcv_nxt;
            spec.flags    = ::tc8::stimulus::kTcpFlagAck
                          | ::tc8::stimulus::kTcpFlagPsh;
            spec.payload.assign(kFullSizedPayloadLen, fill);
            return spec;
        };

        for (std::uint16_t i = 0; i < kBurstSegmentCount; ++i) {
            const std::uint32_t seq =
                injected_seq +
                static_cast<std::uint32_t>(i) *
                    static_cast<std::uint32_t>(kFullSizedPayloadLen);
            // Distinct first byte ('0'..'9') keeps each segment
            // visually identifiable in pcap; exact bytes are not
            // load-bearing — only count and SEQ ranges matter.
            const std::uint8_t fill =
                static_cast<std::uint8_t>('0' + (i % 10U));
            const auto wait = (i == 0)
                                ? std::chrono::milliseconds(0)
                                : kInterSegmentWait;
            emitTcpFrame(cfg, iface, cfg.dut.mac,
                         build_seg(seq, fill), wait);
        }
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                            return "pass";
            case State::Fail_no_handshake_ack:           return "fail:no_dut_handshake_ack";
            case State::Fail_insufficient_dut_acks:      return "fail:dut_emitted_fewer_than_5_acks_for_10_full_sized_segments";
            default:                                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpOutOfOrder05SM, tcp_out_of_order_05)
