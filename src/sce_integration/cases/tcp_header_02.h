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

#include "tcp_header_02_sm.h"

namespace tc8::sce::cases {

using TcpHeader02SM = ::SCE::Generated::tcp_header_02::tcp_header_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader02SM>
    : TcpAnyBase<cases::TcpHeader02SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT accepts TCP packet with valid header fields and ACKs with "
        "the expected Ack Number (RFC 793 §3.9 Event Processing)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};

    // Mechanism: active-OPEN to ESTABLISHED + queryTcpSeqRange + raw-
    // inject in-window data + observe DUT pure ACK with the spec-
    // mandated ack_num. captured.expected_ack_num is populated from
    // (snd_nxt + payload_len) so the SCXML guard can verify the DUT's
    // ack_num advances by exactly the injected payload length per
    // RFC 793 §3.9 "ACK with the expected Ack Number".
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 31U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 31U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) {
            return;
        }

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        const std::uint32_t injected_seq = seq_range->snd_nxt;
        const std::uint32_t payload_len  =
            static_cast<std::uint32_t>(kDataPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = injected_seq;
        data.ack_num  = seq_range->rcv_nxt;
        data.flags    = ::tc8::stimulus::kTcpFlagPsh
                      | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader02SM, tcp_header_02)
