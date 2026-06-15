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

#include "tcp_header_05_sm.h"

namespace tc8::sce::cases {

using TcpHeader05SM = ::SCE::Generated::tcp_header_05::tcp_header_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader05SM>
    : TcpAnyBase<cases::TcpHeader05SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_05";
    static constexpr std::string_view kSpecSection  = "4.8.6.X";
    static constexpr std::string_view kDescription  =
        "DUT accepts TCP packet with Reserved field set to zero "
        "(RFC 793 §3.1, RFC 4413 §4.2.3)";

    static constexpr std::array<std::uint8_t, 4> kDataPayload = {
        0xC0U, 0xDEU, 0xBEU, 0xEFU};

    // Mechanism: same as HEADER_02 but with reserved_override=0
    // explicitly pinned. The default builder path also emits
    // reserved=0; the override makes the assertion textual rather
    // than positional, so a future builder refactor that changes
    // the default reserved nibble cannot silently regress this case.
    //
    // Migrated onto the Tier-2 DUT-control seam: the active OPEN runs through
    // `driveSeamActiveOpen` (ITcpControl), so the case runs unchanged on
    // whichever backend `--dut-control` selected. Only the OPEN prelude is DUT
    // control; the reserved-zero data raw inject is tester-side and stays
    // case-owned harness infrastructure.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 33U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 33U;

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
        data.reserved_override = 0x00U;
        emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        (void)tester_fd;
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader05SM, tcp_header_05)
