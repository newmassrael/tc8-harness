#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
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
    static constexpr std::string_view kSpecSection  = "4.8.6.4";
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
    static constexpr std::uint16_t kUtRecvTimeoutMs = 2000U;

    // Single iteration. Active-OPEN handshake on +94 quad → raw inject
    // PSH+FIN+ACK with 16-byte payload (drives EST→CW + data delivery
    // in one wire segment) → DUT pure ACK with ack=ISN_t+1+16+1 →
    // UT OpReceiveTcpData drains the kernel-queued bytes → byte-match
    // populates captured.ut_received_payload_len. captured.expected_
    // ack_num pre-set to seq_range->snd_nxt + 17 (data + FIN
    // sequence-number consumption).
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& /*scheduler*/) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 94U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        std::vector<std::uint8_t> payload(kPayloadLen, 0xC3U);

        // PSH+FIN+ACK with in-window data. ack=rcv_nxt acks the
        // handshake third-leg; seq=snd_nxt is exactly the next byte
        // tester would have sent. Linux's tcp_data_queue accepts
        // the bytes and tcp_fin transitions DUT EST→CW in a single
        // segment-processing pass.
        ::tc8::stimulus::TcpSegmentSpec fin_data{};
        fin_data.src_port = remote_port;
        fin_data.dst_port = local_port;
        fin_data.seq_num  = seq_range->snd_nxt;
        fin_data.ack_num  = seq_range->rcv_nxt;
        fin_data.flags    = ::tc8::stimulus::kTcpFlagAck
                          | ::tc8::stimulus::kTcpFlagPsh
                          | ::tc8::stimulus::kTcpFlagFin;
        fin_data.payload  = payload;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, fin_data,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto bytes = queryReceivedBytesSync(
            cfg, /*req_id=*/2, /*socket_id=*/1,
            kPayloadLen, kUtRecvTimeoutMs);
        if (bytes.size() == payload.size()
            && std::equal(bytes.begin(), bytes.end(), payload.begin())) {
            c.ut_received_payload_len = kPayloadLen;
        }

        // DUT's data ACK acknowledges 16 bytes of data + 1 byte for
        // the FIN. snd_nxt is the kernel-tracked tester snd_nxt
        // (= ISN_t + 1) at the moment of query; payload + FIN
        // consumes 17 sequence numbers.
        c.expected_ack_num = seq_range->snd_nxt + kPayloadLen + 1U;

        // Tester fd disposal: TCP_REPAIR + close avoids tester FIN
        // egress. The tester socket would otherwise sit in EST seeing
        // a "future ack" from DUT and emit periodic challenge ACKs;
        // those land on a different src (= tester) and are filtered
        // out by SCXML guards but freezing the kernel socket is the
        // cleaner path. The auxiliary listener (returned by
        // driveActiveOpenEstablished) closes when the stimulus body
        // exits — at that point tester has no socket on the 4-tuple.
        silentlyCloseTesterFd(tester_fd);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_data_ack:       return "fail:no_dut_ack_to_received_fin_data_in_cw";
            case State::Fail_dut_rst_in_cw:         return "fail:dut_emitted_rst_in_cw";
            case State::Fail_dut_fin_in_cw:         return "fail:dut_emitted_fin_in_cw_without_close";
            case State::Fail_no_proper_data:        return "fail:dut_did_not_receive_proper_data_in_cw";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive05SM, tcp_call_receive_05)
