#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_header_08_sm.h"

namespace tc8::sce::cases {

using TcpHeader08SM = ::SCE::Generated::tcp_header_08::tcp_header_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader08SM>
    : TcpAnyBase<cases::TcpHeader08SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_08";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT discards TCP packet with Data Offset greater than the "
        "actual segment length (RFC 793 §3.1; Linux pskb_may_pull discard)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xDEU, 0xADU, 0xC0U, 0xDEU};

    // Mechanism: same active-OPEN scaffold + raw-inject + 3 s
    // absence as HEADER_07. The override sets data_offset_override
    // = 0xF (= 60 B header announced) while the actual on-wire
    // segment is 24 B (20 B header + 4 B payload). Linux's
    // pskb_may_pull(skb, doff*4) returns 0 because the IP payload
    // bytes do not satisfy the announced header length, dropping
    // the segment before socket lookup.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 36U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 36U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port             = remote_port;
        data.dst_port             = local_port;
        data.seq_num              = seq_range->snd_nxt;
        data.ack_num              = seq_range->rcv_nxt;
        data.flags                = ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        // Spec literal "Data Offset value greater than the actual
        // value". 0xF announces a 60 B header against a 24 B
        // segment; pskb_may_pull fails and the segment never
        // reaches the EST socket.
        data.data_offset_override = 0x0FU;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_unexpected_ack:        return "fail:dut_acked_segment_with_oversize_data_offset";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader08SM, tcp_header_08)
