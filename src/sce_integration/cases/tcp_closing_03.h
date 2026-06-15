#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_03_sm.h"

namespace tc8::sce::cases {

using TcpClosing03SM = ::SCE::Generated::tcp_closing_03::tcp_closing_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing03SM>
    : TcpAnyBase<cases::TcpClosing03SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP SHOULD allow a received RST segment to include data and "
        "transition to CLOSED state silently (RFC 1122 §4.2.2.12 p87 "
        "RST Segment / RFC 793 §3.4)";

    // 16-byte non-empty payload for the spec's "RST containing some
    // data" wire shape. Pattern bytes 0xA5 chosen distinct from
    // kTesterInitialSeq / ack bytes so a pcap reader can identify the
    // payload region at a glance. Linux discards the data per
    // tcp_validate_incoming → tcp_reset; the bytes are immaterial to
    // the pass criterion (only payload-presence matters per spec).
    static constexpr std::size_t kRstPayloadLen = 16U;

    // Single iteration, backend-agnostic (opcode UT or AUTOSAR
    // testability). Seam active-OPEN (driveSeamActiveOpen) +
    // queryTcpSeqRange → raw-inject RST+ACK with seq=snd_nxt (in-window)
    // and a 16-byte payload → wait for SCXML's spec_silence deadline
    // (3 s) → verify-probe ACK on entry to listening_verify_rst draws
    // DUT RST proving CLOSED. Verify-probe ACK is scheduled via
    // scheduleAfterStateEntry to phase it AFTER the absence window
    // closes, not by wall clock — same shape as FP_06's replay-FIN
    // chaining. Port quad +71 reserves the §4.8.6.8 EST-RST slot.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 71U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        std::vector<std::uint8_t> payload(kRstPayloadLen, 0xA5U);

        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = remote_port;
        rst.dst_port = local_port;
        rst.seq_num  = seq_range->snd_nxt;
        rst.ack_num  = seq_range->rcv_nxt;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst
                     | ::tc8::stimulus::kTcpFlagAck;
        rst.payload  = payload;
        emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                     /*initial_wait=*/std::chrono::milliseconds(0));
        silentlyCloseTesterFd(tester_fd);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;
        const std::uint32_t         probe_seq  = seq_range->snd_nxt + 5U;
        const std::uint32_t         probe_ack  = seq_range->rcv_nxt;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_verify_rst),
            [iface_copy, cfg_copy, dut_mac,
             local_port, remote_port, probe_seq, probe_ack]() {
                ::tc8::stimulus::TcpSegmentSpec ack{};
                ack.src_port = remote_port;
                ack.dst_port = local_port;
                ack.seq_num  = probe_seq;
                ack.ack_num  = probe_ack;
                ack.flags    = ::tc8::stimulus::kTcpFlagAck;
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg_copy, iface_copy, dut_mac, ack,
                    /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing03SM, tcp_closing_03)
