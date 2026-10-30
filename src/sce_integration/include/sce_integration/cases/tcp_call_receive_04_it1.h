#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_call_receive_04_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_call_receive_04_it1_sm.h"

namespace tc8::sce::cases {

using TcpCallReceive04It1SM =
    ::SCE::Generated::tcp_call_receive_04_it1::tcp_call_receive_04_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its three iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_CALL_RECEIVE_04",
    "A DUT's RECEIVE call, made while the connection is ESTABLISHED, in FIN-WAIT-1 or in "
    "FIN-WAIT-2, is handed the segments queued behind it joined into one in-order stream "
    "(RFC 793 §3.9 p58 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallReceive04It1SM>
    : TcpAnyBase<cases::TcpCallReceive04It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // receiveTcp), so it is not measurable on a backend without ITcpControl. The
    // iteration does not half-close the DUT; it asks for nothing beyond that.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId       = "TCP_CALL_RECEIVE_04_IT1";
    static constexpr std::string_view kDescription  =
        "Iteration 1 of TCP_CALL_RECEIVE_04: a RECEIVE call made while the DUT is ESTABLISHED "
        "is handed four queued 32 B segments joined into one 128 B stream";

    // Drive the DUT through an active OPEN to ESTABLISHED, then receive: the trigger
    // injects the 4 x 32 B segments (ack=rcv_nxt acks the third-leg and any prior data);
    // the seam reassembles the forwarded stream into the buffer the DUT's RECEIVE saw.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kPortOffset = kTcpCallReceive04Phase1LocalOffset;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
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

        std::vector<std::uint8_t> expected_payload;
        const auto received = seamTcpControl(ctx.dut).receiveTcp(
            open.conn->socket, cases::kCallReceive04PayloadLen, [&] {
                expected_payload = cases::injectCallReceive04Segments(
                    cfg, ctx.iface, remote_port, local_port,
                    seq->snd_nxt, seq->rcv_nxt, /*pattern=*/0xC0U);
            });
        c.ut_received_payload_len = cases::gradeCallReceive04(received, expected_payload);

        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallReceive04It1SM, tcp_call_receive_04_it1)
