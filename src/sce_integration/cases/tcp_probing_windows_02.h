#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_probing_windows_02_sm.h"

namespace tc8::sce::cases {

using TcpProbingWindows02SM =
    ::SCE::Generated::tcp_probing_windows_02::tcp_probing_windows_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpProbingWindows02SM>
    : TcpAnyBase<cases::TcpProbingWindows02SM> {
    static constexpr std::string_view kCaseId       = "TCP_PROBING_WINDOWS_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.12";
    static constexpr std::string_view kDescription  =
        "DUT TCP MUST treat the receive window as an unsigned 16-bit "
        "number — an MSB-set advertised window does not refuse the "
        "send (RFC 1122 §4.2.2.3 p83 — RFC 793 §3.1).";

    // 1-byte settler used to drive Linux's `tcp_ack_update_window`
    // post-handshake — adding a byte advances ack_seq → snd_wl1 →
    // snd_wnd accepts the new window. Without it a duplicate-ack
    // pure-ACK with same SEQ/ACK as the kernel's third-leg may be
    // dropped by the "no new info" branch and the window stays
    // kernel-default.
    static constexpr std::array<std::uint8_t, 1> kWindowSettlerByte = {'W'};

    // 4-byte SEND payload — small enough to fit one segment; spec
    // step 3 says "issue a SEND request for a data segment" without
    // a size constraint. Distinct ASCII for pcap visibility; not
    // load-bearing.
    static constexpr std::array<std::uint8_t, 4> kSendPayload = {
        'P', 'R', 'B', 'E'};

    // Settle wait between window-update inject and UT SEND so the
    // DUT's tcp_ack_update_window has fired before the application
    // send is enqueued. Linux processes inbound segments in the
    // softirq immediately after pcap capture; 100 ms covers
    // scheduler jitter under parallel workers without bloating the
    // case wall-time.
    static constexpr std::chrono::milliseconds kPostInjectSettle{100};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpProbingWindows02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpProbingWindows02LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        // Window-update inject: 1 B PSH+ACK with window = 0x8000
        // (MSB set). Linux's tcp_ack_update_window accepts because
        // the segment carries new data → ack_seq advances →
        // snd_wl1 advances → tp->snd_wnd = 0x8000.
        ::tc8::stimulus::TcpSegmentSpec spec{};
        spec.src_port = remote_port;
        spec.dst_port = local_port;
        spec.seq_num  = seq_range->snd_nxt;
        spec.ack_num  = seq_range->rcv_nxt;
        spec.flags    = ::tc8::stimulus::kTcpFlagAck
                      | ::tc8::stimulus::kTcpFlagPsh;
        spec.window   = 0x8000U;  // MSB set — RFC 793 §3.1 unsigned
        spec.payload.assign(kWindowSettlerByte.begin(),
                            kWindowSettlerByte.end());

        emitTcpFrame(cfg, iface, cfg.dut.mac, spec,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(kPostInjectSettle);

        dut.tcpControl()->sendTcp(
            open.conn->socket,
            std::vector<std::uint8_t>(kSendPayload.begin(), kSendPayload.end()),
            static_cast<std::uint16_t>(kSendPayload.size()));

        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                            return "pass";
            case State::Fail_no_handshake_ack:           return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_data_segment:        return "fail:dut_did_not_send_data_after_msb_set_window_advertisement";
            default:                                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpProbingWindows02SM, tcp_probing_windows_02)
