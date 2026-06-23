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

#include "tcp_call_receive_05_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive05SM =
    ::SCE::Generated::tcp_call_receive_05::tcp_call_receive_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallReceive05SM>
    : TcpAnyBase<cases::TcpCallReceive05SM> {
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_05";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT state MUST return queued data to the "
        "application on a RECEIVE call (RFC 793 §3.9 p59 Event "
        "Processing). PSH+FIN+ACK segment with payload drives the "
        "EST→CW transition while delivering data; UT recv drains "
        "the bytes and the wire-side data ACK proves end-to-end "
        "FIN+data processing";

    // 16-byte payload pattern. Distinct byte from sibling _03 (0xA5), _07
    // (0x69), _09 (0x5A) so a stray data segment in pcap can be
    // attributed to the correct case ID.
    static constexpr std::uint16_t kPayloadLen = 16U;

    // Single iteration, backend-agnostic (opcode UT or AUTOSAR testability).
    // Seam active-OPEN on +94 quad → snapshot tester snd_nxt / rcv_nxt → seam
    // receive whose trigger raw-injects a PSH+FIN+ACK with a 16-byte payload
    // (drives EST→CW + data delivery in one wire segment) → the DUT in CW emits
    // a pure data ACK with ack=ISN_t+1+16+1 → the seam returns the drained
    // bytes → byte-match populates captured.ut_received_payload_len.
    // captured.expected_ack_num pre-set to snd_nxt + 17 (data + FIN
    // sequence-number consumption) so the SCXML guard checks the data ACK is
    // for our data+FIN.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = kTcpCallReceive05LocalOffset;
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

        auto& tcp = seamTcpControl(dut);

        const std::vector<std::uint8_t> payload(kPayloadLen, 0xC3U);

        // Receive in EST→CW: the trigger raw-injects a PSH+FIN+ACK carrying the
        // 16-byte data. ack=rcv_nxt acks the handshake third-leg; seq=snd_nxt is
        // the next byte the tester would have sent. Linux's tcp_data_queue
        // accepts the bytes and tcp_fin transitions the DUT EST→CW in a single
        // segment-processing pass; the seam returns what the DUT received.
        const auto received = tcp.receiveTcp(
            open.conn->socket, kPayloadLen, [&] {
                ::tc8::stimulus::TcpSegmentSpec fin_data{};
                fin_data.src_port = remote_port;
                fin_data.dst_port = local_port;
                fin_data.seq_num  = seq_range->snd_nxt;
                fin_data.ack_num  = seq_range->rcv_nxt;
                fin_data.flags    = ::tc8::stimulus::kTcpFlagAck
                                  | ::tc8::stimulus::kTcpFlagPsh
                                  | ::tc8::stimulus::kTcpFlagFin;
                fin_data.payload  = payload;
                emitTcpFrame(cfg, iface, cfg.dut.mac, fin_data,
                             /*initial_wait=*/std::chrono::milliseconds(0));
            });
        if (received && *received == payload) {
            c.ut_received_payload_len = kPayloadLen;
        }

        // DUT's data ACK acknowledges 16 bytes of data + 1 byte for the FIN.
        // snd_nxt is the kernel-tracked tester snd_nxt (= ISN_t + 1) at query
        // time; payload + FIN consumes 17 sequence numbers.
        c.expected_ack_num = seq_range->snd_nxt + kPayloadLen + 1U;

        // Tester fd disposal: silentlyCloseTesterFd (TCP_REPAIR + close) avoids
        // a tester FIN egress. The tester socket would otherwise sit in EST
        // seeing a "future ack" from the DUT and emit periodic challenge ACKs;
        // those land on the tester src and are filtered by the SCXML guards, but
        // freezing the kernel socket is cleaner. open.listener closes when the
        // stimulus body exits — at that point the tester has no socket on the
        // 4-tuple.
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive05SM, tcp_call_receive_05)
