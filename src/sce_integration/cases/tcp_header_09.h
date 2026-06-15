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

#include "tcp_header_09_sm.h"

namespace tc8::sce::cases {

using TcpHeader09SM = ::SCE::Generated::tcp_header_09::tcp_header_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader09SM>
    : TcpAnyBase<cases::TcpHeader09SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT discards TCP packet with Checksum = 0 and sends no ACK "
        "back (RFC 793 §3.1; TCP checksum is mandatory)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xFAU, 0xCEU, 0xC0U, 0xFFU};

    // Mechanism: same active-OPEN scaffold + raw-inject + 3 s
    // absence as HEADER_07/08. force_zero_tcp_checksum forces the
    // checksum field to absolute 0x0000 after pseudo-header
    // computation; Linux's tcp_checksum_complete sees mismatch
    // against the actual one's-complement sum and drops.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 37U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 37U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port                = remote_port;
        data.dst_port                = local_port;
        data.seq_num                 = seq_range->snd_nxt;
        data.ack_num                 = seq_range->rcv_nxt;
        data.flags                   = ::tc8::stimulus::kTcpFlagPsh
                                     | ::tc8::stimulus::kTcpFlagAck;
        data.payload.assign(kDataPayload.begin(), kDataPayload.end());
        // Spec literal "Checksum = 0". Distinct from corrupt_tcp_
        // checksum (XOR perturbation): force_zero pins absolute
        // 0x0000, which Linux's tcp_checksum_complete rejects against
        // the actual non-zero pseudo-header sum.
        data.force_zero_tcp_checksum = true;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader09SM, tcp_header_09)
