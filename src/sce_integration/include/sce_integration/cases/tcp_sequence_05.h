#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_sequence_05_sm.h"

namespace tc8::sce::cases {

using TcpSequence05SM =
    ::SCE::Generated::tcp_sequence_05::tcp_sequence_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence05SM>
    : TcpAnyBase<cases::TcpSequence05SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_05";
    static constexpr std::string_view kDescription  =
        "From ESTABLISHED, DUT acknowledges each tester data segment "
        "with a cumulative ACK at the expected Ack Number "
        "(RFC 793 §3.4 / §3.7).";

    static constexpr std::array<std::uint8_t, 4> kSegPayload = {
        0xC0U, 0xDEU, 0xCAU, 0xFEU};
    static constexpr std::uint32_t kSegLen =
        static_cast<std::uint32_t>(kSegPayload.size());

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // The raw-injected tester source 4-tuple has no real kernel
        // socket, so any post-handshake DUT-origin ACK landing on
        // (tester_src_port, listen_port) would draw an auto-RST from
        // the tester kernel — tearing the DUT's ESTABLISHED state down
        // mid-segment-stream. The seam ACCEPT's internal TesterAutoRstDrop
        // scope is bounded to the handshake, so the SEQUENCE_05 trait holds
        // an outer-scope drop covering all three data segments + their
        // cumulative ACKs.
        TesterAutoRstDrop rst_drop(cfg);

        const auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpSequence05ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence05TesterSrcPort,
            /*tester_isn=*/kTesterInitialSeq);
        if (!open.conn) return;  // no accepted connection ⇒ no DUT to ack/close

        // Three 4 B segments spaced past the RFC 1122 §4.2.3.2
        // delayed-ACK ceiling (kDelayedAckSettle, 600 ms). The spec
        // pass criterion is one ACK per received segment; a quickack
        // stack (Linux) ACKs each immediately, while a delayed-ACK
        // stack (lwIP) would coalesce segments arriving within ~250 ms
        // into a single cumulative ACK — failing the per-segment chain
        // for a test-design reason, not a conformance gap. Spacing the
        // segments beyond the ceiling lets the delayed-ACK timer fire
        // for each segment before the next arrives, so both DUT classes
        // emit the per-segment cumulative ACKs the SCXML walks. The
        // final gap also outlasts the close-RST race (see
        // ACKNOWLEDGEMENT_03), so seg 3's ACK is observed before
        // teardown.
        std::uint32_t seg_seq = kTesterInitialSeq + 1U;
        for (int i = 0; i < 3; ++i) {
            ::tc8::stimulus::TcpSegmentSpec data{};
            data.src_port = kTcpSequence05TesterSrcPort;
            data.dst_port = kTcpSequence05ListenPort;
            data.seq_num  = seg_seq;
            data.ack_num  = open.dut_isn + 1U;
            data.flags    = ::tc8::stimulus::kTcpFlagPsh
                          | ::tc8::stimulus::kTcpFlagAck;
            data.payload.assign(kSegPayload.begin(), kSegPayload.end());
            emitTcpFrame(cfg, iface, cfg.dut.mac, data,
                         /*initial_wait=*/std::chrono::milliseconds(0));
            seg_seq += kSegLen;
            std::this_thread::sleep_for(kDelayedAckSettle);
        }

        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence05SM, tcp_sequence_05)
