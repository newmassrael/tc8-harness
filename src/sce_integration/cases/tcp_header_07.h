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

#include "tcp_header_07_sm.h"

namespace tc8::sce::cases {

using TcpHeader07SM = ::SCE::Generated::tcp_header_07::tcp_header_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader07SM>
    : TcpAnyBase<cases::TcpHeader07SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT discards TCP packet with Data Offset < 5 "
        "(RFC 793 §3.1; Linux tcp_v4_rcv bad_packet)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xBAU, 0xADU, 0xF0U, 0x0DU};

    // Mechanism: same active-OPEN scaffold as HEADER_02 but the raw-
    // inject sets data_offset_override=4 (< RFC 793 minimum of 5).
    // Linux's tcp_v4_rcv falls into the bad_packet path before the
    // segment reaches the EST socket; no DUT ACK fires. The 3 s
    // absence window confirms silent-drop.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 35U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 35U;

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
        // Spec literal "Data Offset value less than 5". RFC 793 §3.1
        // mandates >= 5; Linux gates this in tcp_v4_rcv before any
        // socket lookup, so the EST socket never sees the segment.
        data.data_offset_override = 0x04U;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader07SM, tcp_header_07)
