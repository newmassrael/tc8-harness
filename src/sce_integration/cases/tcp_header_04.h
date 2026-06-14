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

#include "tcp_header_04_sm.h"

namespace tc8::sce::cases {

using TcpHeader04SM = ::SCE::Generated::tcp_header_04::tcp_header_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader04SM>
    : TcpAnyBase<cases::TcpHeader04SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT discards TCP packet whose source port differs from the "
        "established peer's port (RFC 793 §3.1 / §3.9 4-tuple demux)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xFFU, 0xEEU, 0x00U};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 32U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 32U;
        // PORT2 — deliberately distant from any §4.8 listener port to
        // avoid an accidental kernel-listener match. +132 places it
        // ~100 above the §4.8.6.X HEADER cluster's +30..+38 block.
        const std::uint16_t wrong_remote_port =
            static_cast<std::uint16_t>(kBasicsActiveRemotePort + 132U);

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = wrong_remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_unexpected_ack:        return "fail:dut_acked_segment_with_wrong_source_port";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader04SM, tcp_header_04)
