#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_closing_07_sm.h"

namespace tc8::sce::cases {

using TcpClosing07SM = ::SCE::Generated::tcp_closing_07::tcp_closing_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing07SM>
    : TcpAnyBase<cases::TcpClosing07SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP in FIN-WAIT-1 state MUST honour RECEIVE calls and ACK "
        "incoming data while remaining in FIN-WAIT-1 (RFC 793 §3.5 "
        "p38 Closing a Connection)";

    // 16-byte payload pattern. Distinct byte from §_03 (0xA5) and §_09
    // (0x5A) so a pcap reader can attribute a stray data segment to
    // the correct case ID.
    static constexpr std::uint16_t kPayloadLen = 16U;

    // UT recv timeout: well past the round-trip time but bounded so a
    // tc8-dut hang doesn't burn the case timeout.
    static constexpr std::uint16_t kUtRecvTimeoutMs = 2000U;

    // Single iteration. Active-OPEN handshake on +73 quad → install
    // shared_ptr<TesterAutoAckDrop> case-lifetime via
    // scheduler.schedule(120s) keepalive lambda → UT close → DUT FIN
    // (tester kernel ACK suppressed) → raw inject 16-byte data with
    // ack=ISN_d+1 (= SND.UNA, doesn't ack DUT FIN) → wait → UT
    // OpReceiveTcpData drains the kernel-queued bytes → byte-match
    // populates captured.ut_received_payload_len. captured.expected_
    // ack_num pre-set to the spec-conformant DUT ACK number
    // (ISN_t + 1 + kPayloadLen) so the SCXML guard checks the data
    // ACK is actually for our data (not a re-tx ACK with a stale
    // ack_num).
    //
    // Tester fd intentionally left open through harness teardown —
    // closing it would either (a) emit FIN → drive DUT FW1 → CLOSING
    // and break "remain in FW1", or (b) silentlyCloseTesterFd would
    // dispose the kernel socket so any DUT FIN re-tx draws closed-
    // port RST, again breaking "remain in FW1". A long-life
    // shared_ptr<TesterAutoAckDrop> capture in a 120 s scheduled
    // lambda holds the iptables rule alive past the SCXML deadline;
    // the runner dtor at case end releases the shared_ptr → AckDrop
    // dtor → iptables rule removed.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 73U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto ack_drop = std::make_shared<TesterAutoAckDrop>(cfg);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.arp.dut_real_mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) return;

        // shutdown(WR) — kernel emits FIN, socket transitions EST→FW1,
        // read side stays open so OpReceiveTcpData can drain bytes.
        // Using OpCloseTcpSocket here would call ::close on tc8-dut
        // which (a) erases the socket_id from tcp_listeners_ so a
        // subsequent OpReceiveTcpData returns kStatusUnknownSocket and
        // (b) drives Linux's tcp_data_queue path to RST on incoming
        // data because the user-space side is closed — both break the
        // "remain in FW1" / "DUT receives proper data" assertions.
        // Spec §4.8.6.8 _07 lists "Support of ETM Service Primitive
        // SHUTDOWN" as an explicit prerequisite (p351).
        sendShutdownTcpSocketWrRequest(
            cfg, iface, cfg.arp.dut_real_mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        std::vector<std::uint8_t> payload(kPayloadLen, 0x69U);

        ::tc8::stimulus::TcpSegmentSpec data{};
        data.src_port = remote_port;
        data.dst_port = local_port;
        data.seq_num  = seq_range->snd_nxt;          // ISN_t + 1
        data.ack_num  = seq_range->rcv_nxt;          // ISN_d + 1, doesn't ack DUT FIN
        data.flags    = ::tc8::stimulus::kTcpFlagAck
                      | ::tc8::stimulus::kTcpFlagPsh;
        data.payload  = payload;
        emitTcpFrame(cfg, iface, cfg.arp.dut_real_mac, data,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        const auto bytes = queryReceivedBytesSync(
            cfg, /*req_id=*/3, /*socket_id=*/1,
            kPayloadLen, kUtRecvTimeoutMs);
        if (bytes.size() == payload.size()
            && std::equal(bytes.begin(), bytes.end(), payload.begin())) {
            c.ut_received_payload_len = kPayloadLen;
        }

        // Spec-conformant DUT ack to our data: ack_num = tester snd_nxt
        // (ISN_t+1) + kPayloadLen.
        c.expected_ack_num = seq_range->snd_nxt + kPayloadLen;

        // Keep AckDrop alive past the SCXML's remain_in_fw1 deadline.
        // The runner's dtor (at case end) releases the queued
        // ScheduledStimulus → shared_ptr release → iptables rule
        // removed cleanly. 120 s is well past any plausible case
        // timeout (CASE_TIMEOUT_SEC for _07 = 30 s).
        scheduler.schedule(
            std::chrono::seconds(120),
            [ack_drop]() { (void)ack_drop; });

        // Tester fd left open: the kernel socket is in CW after
        // receiving DUT's FIN; further DUT FIN re-tx draws kernel-
        // queued ACKs which AckDrop discards, keeping DUT in FW1.
        (void)tester_fd;
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_fin:            return "fail:no_dut_close_fin";
            case State::Fail_no_dut_data_ack:       return "fail:no_dut_ack_to_received_data_in_fw1";
            case State::Fail_dut_rst_in_fw1:        return "fail:dut_emitted_rst_in_fw1";
            case State::Fail_no_proper_data:        return "fail:dut_did_not_receive_proper_data_in_fw1";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing07SM, tcp_closing_07)
