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

#include "tcp_header_06_sm.h"

namespace tc8::sce::cases {

using TcpHeader06SM = ::SCE::Generated::tcp_header_06::tcp_header_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader06SM>
    : TcpAnyBase<cases::TcpHeader06SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_06";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT ignores Reserved field non-zero value and accepts the TCP "
        "packet (RFC 4413 §4.2.3 Reserved)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xFEU, 0xEDU, 0xFAU, 0xCEU};

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 34U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 34U;

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
            static_cast<std::uint32_t>(kDataPayload.size());
        c.expected_ack_num = injected_seq + payload_len;

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port          = remote_port;
        data.dst_port          = local_port;
        data.seq_num           = injected_seq;
        data.ack_num           = seq_range->rcv_nxt;
        data.flags             = ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        // 0x0F = all four RFC 793 §3.1 reserved bits set. RFC 4413
        // §4.2.3 mandates the receiver MUST ignore the Reserved
        // field; spec literal "Reserved field different from zero"
        // is satisfied by the maximal value to also catch any
        // implementation that masks individual bits selectively.
        data.reserved_override = 0x0FU;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader06SM, tcp_header_06)
