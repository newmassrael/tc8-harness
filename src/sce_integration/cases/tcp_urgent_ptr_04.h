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

#include "tcp_urgent_ptr_04_sm.h"

namespace tc8::sce::cases {

using TcpUrgentPtr04SM =
    ::SCE::Generated::tcp_urgent_ptr_04::tcp_urgent_ptr_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUrgentPtr04SM>
    : TcpAnyBase<cases::TcpUrgentPtr04SM> {
    static constexpr std::string_view kCaseId       = "TCP_URGENT_PTR_04";
    static constexpr std::string_view kSpecSection  = "4.8.6.14";
    static constexpr std::string_view kDescription  =
        "Data following the urgent pointer (non-urgent data) MUST NOT "
        "be delivered to the user in the same buffer with preceding "
        "urgent data (RFC 793 §3.7 Interfaces).";

    // 6-byte payload + urgent_pointer=3 places the last urgent byte
    // at SEG.SEQ+2 (Linux BSD interpretation: ptr-- to 2 then add
    // SEQ). Payload offset 2 = 'C' → tc8-dut's recv(MSG_OOB)
    // returns one byte == 'C'. The trailing "DEF" is the
    // non-urgent tail asserted to be absent from the OOB buffer.
    static constexpr std::array<std::uint8_t, 6> kUrgPayload = {
        'A', 'B', 'C', 'D', 'E', 'F'};
    static constexpr std::uint16_t kUrgentPointer       = 3U;
    static constexpr std::uint8_t  kExpectedUrgentByte  = 'C';
    // recv(MSG_OOB) is opcode-only — the standard AUTOSAR testability protocol
    // has no urgent/OOB receive SP, so the case is honestly capability-skipped on
    // the testability backend (Tier 2 2b#4) rather than failed.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpRecvOob;

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort  + kTcpUrgentPtr04LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpUrgentPtr04LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            ::close(tester_fd);
            return;
        }

        ::tc8::stimulus::TcpSegmentSpec urg_seg{};
        urg_seg.src_port       = remote_port;
        urg_seg.dst_port       = local_port;
        urg_seg.seq_num        = seq_range->snd_nxt;
        urg_seg.ack_num        = seq_range->rcv_nxt;
        urg_seg.flags          = ::tc8::stimulus::kTcpFlagUrg
                               | ::tc8::stimulus::kTcpFlagPsh
                               | ::tc8::stimulus::kTcpFlagAck;
        urg_seg.urgent_pointer = kUrgentPointer;
        urg_seg.payload.assign(kUrgPayload.begin(), kUrgPayload.end());
        emitTcpFrame(cfg, iface, cfg.dut.mac, urg_seg,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        // Buffer-of-size-6 satisfies spec step 4 "data buffer having size equal
        // to the size of the incoming data segment". The spec step 5 assertion is
        // that the call returns only the urgent data — recv(MSG_OOB) fulfils that
        // structurally (the 5 non-urgent bytes stay queued for a separate normal
        // recv()). seamTcpRecvOob asserts non-null: the capability gate has
        // already skipped any backend lacking kCapTcpRecvOob.
        const auto received = seamTcpRecvOob(dut).receiveTcpOob(
            open.conn->socket, static_cast<std::uint16_t>(kUrgPayload.size()));
        if (received && received->size() == 1U && (*received)[0] == kExpectedUrgentByte) {
            c.ut_received_payload_len = 1U;
        }

        seamTcpControl(dut).closeTcp(open.conn->socket);
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUrgentPtr04SM, tcp_urgent_ptr_04)
