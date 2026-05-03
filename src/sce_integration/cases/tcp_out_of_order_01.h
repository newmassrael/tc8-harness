#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_out_of_order_01_sm.h"

namespace tc8::sce::cases {

using TcpOutOfOrder01SM =
    ::SCE::Generated::tcp_out_of_order_01::tcp_out_of_order_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpOutOfOrder01SM>
    : TcpAnyBase<cases::TcpOutOfOrder01SM> {
    static constexpr std::string_view kCaseId       = "TCP_OUT_OF_ORDER_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.10";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST acknowledge a full-sized segment within 0.5 sec "
        "(RFC 1122 §4.2.3.2 p96 — When to Send an ACK Segment, MUST).";

    // Full-sized segment per RFC 879 / RFC 1122 §4.2.2.6 = MSS bytes.
    // veth's default MTU 1500 admits IP 20 + TCP 20 + payload 1460 =
    // 1500. Larger payloads would be fragmented by IP, defeating the
    // "single full-sized segment" assertion.
    static constexpr std::uint16_t kFullSizedPayloadLen = 1460U;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpOutOfOrder01LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpOutOfOrder01LocalOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;
        c.expected_ack_num = injected_seq +
            static_cast<std::uint32_t>(kFullSizedPayloadLen);

        ::tc8::stimulus::TcpSegmentSpec spec{};
        spec.src_port = remote_port;
        spec.dst_port = local_port;
        spec.seq_num  = injected_seq;
        spec.ack_num  = seq_range->rcv_nxt;
        spec.flags    = ::tc8::stimulus::kTcpFlagAck
                      | ::tc8::stimulus::kTcpFlagPsh;
        spec.payload.assign(kFullSizedPayloadLen, std::uint8_t{'F'});

        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, spec,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_no_handshake_ack:             return "fail:no_dut_handshake_ack";
            case State::Fail_no_data_ack_within_500ms:     return "fail:dut_did_not_ack_full_sized_segment_within_500ms";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpOutOfOrder01SM, tcp_out_of_order_01)
