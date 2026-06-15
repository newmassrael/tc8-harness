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

#include "tcp_call_receive_04_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive04SM =
    ::SCE::Generated::tcp_call_receive_04::tcp_call_receive_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallReceive04SM>
    : TcpAnyBase<cases::TcpCallReceive04SM> {
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.4";
    static constexpr std::string_view kDescription  =
        "TCP MUST reassemble queued incoming segments and return the "
        "data to a RECEIVE call in EST / FIN-WAIT-1 / FIN-WAIT-2 "
        "(RFC 793 §3.9 p58 Event Processing). 3-iter compound: 4 × "
        "32 B segments per phase, single 128 B UT recv per phase";

    // 4 segments × 32 bytes = 128 bytes total per phase. Stays well
    // under kMaxPayload (256) so the single UT recv response carries
    // every byte without splitting; large enough that reassembly is
    // not trivially "one segment delivered as one segment".
    static constexpr std::uint16_t kSegmentSize     = 32U;
    static constexpr std::uint16_t kSegmentCount    = 4U;
    static constexpr std::uint16_t kPayloadLen      =
        kSegmentSize * kSegmentCount;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1Established(c, cfg, iface, dut);

        // Phases 2 + 3 deferred via scheduleAfterStateEntry. Each
        // phase emits its own active-OPEN handshake, FIN egress, and
        // 4-segment data inject — wiring those to the matching SCXML
        // observation state ensures the wire events arrive while the
        // phase's listening transitions are armed (otherwise phase 1's
        // 5 s deadlines would consume them or the SCXML would
        // transition past the phase before its events appear).
        //
        // cfg / iface are captured by value (the outer stimulus returns
        // before the lambdas fire); the DUT-control handle is owned by
        // the CLI for the whole run, so the deferred phases capture a
        // raw pointer to it (the FP_09 idiom — a reference cannot be
        // re-seated into the lambda capture list).
        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        ::tc8::sce::IDutControl*     dut_ptr  = &dut;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, &c, dut_ptr]() {
                runPhase2FinWait1(c, cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, &c, dut_ptr]() {
                runPhase3FinWait2(c, cfg_copy, iface_copy, *dut_ptr);
            });
    }

private:
    // Inject N consecutive small data segments with seq advancing by
    // kSegmentSize per iteration. `ack_value` stays constant per phase
    // — for FW1 it is non-acking-ack (= snd.una of DUT, doesn't ack
    // the FIN); for EST + FW2 it acks the third-leg / DUT FIN
    // respectively. Pattern byte distinguishes phase output in pcap.
    static std::vector<std::uint8_t> injectSegments(
        const ::tc8::TestConfig& cfg,
        std::string_view iface,
        std::uint16_t src_port,
        std::uint16_t dst_port,
        std::uint32_t seq_base,
        std::uint32_t ack_value,
        std::uint8_t  pattern) {
        std::vector<std::uint8_t> total;
        total.reserve(kPayloadLen);
        for (std::uint16_t i = 0U; i < kSegmentCount; ++i) {
            std::vector<std::uint8_t> chunk(kSegmentSize,
                                             static_cast<std::uint8_t>(pattern + i));
            ::tc8::stimulus::TcpSegmentSpec seg{};
            seg.src_port = src_port;
            seg.dst_port = dst_port;
            seg.seq_num  = seq_base + (i * kSegmentSize);
            seg.ack_num  = ack_value;
            seg.flags    = ::tc8::stimulus::kTcpFlagAck
                         | ::tc8::stimulus::kTcpFlagPsh;
            seg.payload  = chunk;
            ::tc8::sce::tcp::emitTcpFrame(
                cfg, iface, cfg.dut.mac, seg,
                /*initial_wait=*/std::chrono::milliseconds(0));
            total.insert(total.end(), chunk.begin(), chunk.end());
            // Tiny gap between segments — keeps Linux from coalescing
            // them in the receive queue before the application reads;
            // either coalescing or non-coalescing is RFC-conformant
            // (the spec asserts only on the reassembled buffer the
            // application sees), so the gap is conservative.
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return total;
    }

    static void runPhase1Established(Captured& c,
                                     const ::tc8::TestConfig& cfg,
                                     std::string_view iface,
                                     ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = 95U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        const auto seq = queryTcpSeqRange(tester_fd);
        if (!seq.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        // Receive in EST: the trigger injects the 4 × 32 B segments (ack=rcv_nxt
        // acks the third-leg and any prior data); the seam reassembles the
        // forwarded stream into the buffer the DUT's RECEIVE saw.
        std::vector<std::uint8_t> expected_payload;
        const auto received = seamTcpControl(dut).receiveTcp(
            open.conn->socket, kPayloadLen, [&] {
                expected_payload = injectSegments(
                    cfg, iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xC0U);
            });
        if (received && *received == expected_payload) {
            c.ut_received_payload_len_p1 = kPayloadLen;
        }

        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase2FinWait1(Captured& c,
                                  const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = 96U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        // Suppress the tester kernel's auto-ACK so the DUT data-ACKs emitted
        // during the 4-segment inject are NOT coalesced into a pure ACK that
        // would advance the DUT FW1→FW2. The drop scope spans the inject loop
        // and the seam receive (which blocks until the bytes are drained) — the
        // critical window — then lifts at function return; the FW1 sibling
        // TCP_CLOSING_07 holds the same rule via a scheduled keepalive instead.
        TesterAutoAckDrop ack_drop(cfg);

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;
        // Snapshot tester snd_nxt / rcv_nxt BEFORE shutdown so the FIN's
        // seq-number consumption isn't reflected in rcv_nxt. The returned
        // rcv_nxt = ISN_d + 1 (post-handshake, no FIN processed yet) is exactly
        // the DUT's SND.UNA after FIN egress, so it doubles as the
        // spec-acceptable "doesn't ack FIN" ack value.
        const auto seq = queryTcpSeqRange(tester_fd);
        if (!seq.has_value()) return;

        auto& tcp = seamTcpControl(dut);

        // shutdown(WR) — DUT emits FIN, socket EST→FW1; the read side stays open
        // so the seam receive still drains the queued bytes.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Receive in FW1: ack = rcv_nxt (= ISN_d + 1 = SND.UNA). Acceptable per
        // RFC 793 §3.4 (in [snd.una, snd.nxt)) but does NOT ack the DUT FIN — the
        // DUT stays in FW1 across the data inject window.
        std::vector<std::uint8_t> expected_payload;
        const auto received = tcp.receiveTcp(
            open.conn->socket, kPayloadLen, [&] {
                expected_payload = injectSegments(
                    cfg, iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xD0U);
            });
        if (received && *received == expected_payload) {
            c.ut_received_payload_len_p2 = kPayloadLen;
        }

        // Tester fd intentionally leaked through case end — closing would either
        // emit FIN (drives DUT FW1→CLOSING) or silentlyCloseTesterFd would
        // dispose the kernel socket so a DUT FIN re-tx draws closed-port RST.
        // Same rationale as TCP_CLOSING_07.
        (void)tester_fd;
        (void)ack_drop;
    }

    static void runPhase3FinWait2(Captured& c,
                                  const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = 97U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        auto& tcp = seamTcpControl(dut);

        // shutdown(WR) → DUT FIN → tester kernel auto-ACK (no AckDrop) → DUT
        // FW1→FW2. The auto-ACK consumes the FIN sequence number so the tester
        // rcv_nxt advances past ISN_d + 1.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        const auto seq = queryTcpSeqRange(tester_fd);
        if (!seq.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        // Receive in FW2: ack = rcv_nxt (= ISN_d + 2, post-FIN) already acks the
        // DUT FIN — DUT.snd.una = rcv_nxt. The data segments are accepted
        // regardless of FIN-ack semantics; the DUT stays in FW2 across the
        // inject window.
        std::vector<std::uint8_t> expected_payload;
        const auto received = tcp.receiveTcp(
            open.conn->socket, kPayloadLen, [&] {
                expected_payload = injectSegments(
                    cfg, iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xE0U);
            });
        if (received && *received == expected_payload) {
            c.ut_received_payload_len_p3 = kPayloadLen;
        }

        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive04SM, tcp_call_receive_04)
