#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_checksum_02_sm.h"

namespace tc8::sce::cases {

using TcpChecksum02SM = ::SCE::Generated::tcp_checksum_02::tcp_checksum_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpChecksum02SM>
    : TcpAnyBase<cases::TcpChecksum02SM> {
    static constexpr std::string_view kCaseId       = "TCP_CHECKSUM_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.2";
    static constexpr std::string_view kDescription  =
        "Receiver TCP MUST check the checksum and MUST NOT acknowledge "
        "in case of an error (RFC 1122 §4.2.2.7 p86 TCP Checksum)";

    // Spec Test Procedure (v3.0 p301-p320.txt:161):
    //   1. TESTER: Cause DUT ESTABLISHED — active OPEN.
    //   2. TESTER: Send a data segment with incorrect checksum.
    //   3. DUT:    Do not send ACK (absence-pass).
    //
    // Migrated onto the Tier-2 DUT-control seam: the active OPEN runs
    // through `driveSeamActiveOpen` (ITcpControl), so the case runs unchanged
    // on whichever backend `--dut-control` selected (opcode UT or AUTOSAR
    // testability). Only the OPEN prelude is DUT control; the corrupt-checksum
    // raw inject is tester-side and stays case-owned harness infrastructure.
    // No seam close: the connection is intentionally left open (see the
    // tail comment) so a teardown FIN exchange cannot false-fail the absence
    // guard.
    //
    // The kernel-driven handshake leaves the tester accept fd in
    // ESTABLISHED with `snd_nxt` = ISN_tester+1, `rcv_nxt` =
    // ISN_dut+1. Reading these via TCP_REPAIR + TCP_QUEUE_SEQ
    // (queryTcpSeqRange) provides the in-window SEQ/ACK pair the
    // raw-inject builder needs — without them, the DUT would drop the
    // segment for window violation and the absence-pass would be
    // false-positive ("DUT didn't ACK because segment was off-window",
    // not "DUT didn't ACK because checksum was wrong").
    //
    // The 4 B payload mirrors CHECKSUM_01/03 — small, non-empty so
    // payload_len > 0 and the segment occupies a non-trivial sequence
    // span. Content is opaque to the spec.
    static constexpr std::array<std::uint8_t, 4> kChecksumPayload = {
        0xDEU, 0xADU, 0xBEU, 0xEFU};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpChecksum02LocalOffset,
            kBasicsActiveRemotePort + kTcpChecksum02LocalOffset);

        const int tester_fd = open.listener.acceptOne();
        if (tester_fd >= 0) {
            // Snapshot the tester kernel's view of the connection's
            // SEQ space so the corrupt-checksum raw inject lands
            // in-window. Done while no application data has been sent
            // — snd_nxt is ISN_t+1 (one byte forward from SYN), which
            // matches what DUT expects as the next inbound SEQ.
            const auto seq_range = queryTcpSeqRange(tester_fd);
            if (seq_range.has_value()) {
                ::tc8::stimulus::TcpSegmentSpec spec{};
                spec.src_port = kBasicsActiveRemotePort + kTcpChecksum02LocalOffset;
                spec.dst_port = kBasicsActiveLocalPort  + kTcpChecksum02LocalOffset;
                spec.seq_num  = seq_range->snd_nxt;
                spec.ack_num  = seq_range->rcv_nxt;
                spec.flags    = ::tc8::stimulus::kTcpFlagPsh
                              | ::tc8::stimulus::kTcpFlagAck;
                spec.payload.assign(kChecksumPayload.begin(),
                                    kChecksumPayload.end());
                spec.corrupt_tcp_checksum = true;
                const auto tcp_bytes = ::tc8::stimulus::buildTcpSegment(
                    cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, spec);

                ::tc8::stimulus::Ipv4FrameSpec ip_spec{};
                ip_spec.dst_mac     = cfg.dut.mac;
                ip_spec.src_ip      = cfg.ipv4.tester_ip;
                ip_spec.dst_ip      = cfg.ipv4.dut_iface_ip;
                ip_spec.ip_protocol = ::tc8::stimulus::kIpProtoTcp;
                ::tc8::stimulus::IpBootTiming timing{};
                timing.initial_wait = std::chrono::milliseconds(0);
                ::tc8::stimulus::emitIpv4Frame(iface, ip_spec, tcp_bytes,
                                                timing);
            }
            // Intentionally do NOT close tester_fd or send UT
            // OpCloseTcpSocket here. A close-driven FIN exchange
            // (tester FIN → DUT bare-ACK to FIN → DUT FIN+ACK)
            // generates DUT-origin pure-ACK segments that match the
            // SCXML's listening_absence fail guard's flag profile
            // (ACK=1, SYN=0, FIN=0, RST=0, payload=0), which would
            // false-fail the case on Linux versions whose delayed-ACK
            // does not piggyback the FIN. The connection stays open
            // until process exit (harness teardown after SCXML pass);
            // tc8-dut's accepted_fd is closed by tc8-dut's RAII on
            // its own SIGKILL by smoke-test, well after the harness's
            // pcap source has been torn down — no post-test events
            // leak into a future case's window.
            (void)tester_fd;
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_unexpected_ack:        return "fail:dut_acked_corrupt_checksum_data";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpChecksum02SM, tcp_checksum_02)
