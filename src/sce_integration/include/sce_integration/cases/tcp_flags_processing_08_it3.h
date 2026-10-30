#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_08_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_08_it3_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08It3SM =
    ::SCE::Generated::tcp_flags_processing_08_it3::tcp_flags_processing_08_it3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08It3SM>
    : TcpAnyBase<cases::TcpFlagsProcessing08It3SM> {
    // Drives the DUT to SYN-SENT through a non-establishing active OPEN (the SYN goes
    // unanswered). The opcode UT's non-blocking openTcpActive worker leaves the socket in
    // SYN-SENT and returns at once; the AUTOSAR testability CONNECT SP instead blocks until the
    // handshake establishes (or times out) and so cannot represent a sustained SYN-SENT.
    // Declaring kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case on a
    // testability backend rather than fail it: the standard's limit, not a DUT fault.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_08_IT3";
    static constexpr std::string_view kDescription =
        "Iteration 3 of TCP_FLAGS_PROCESSING_08: a bare FIN sent to a DUT in SYN-SENT draws no "
        "response";

    // Active-OPEN via driveSeamSynSentOpen on (kBasicsActiveLocalPort + 52,
    // kBasicsActiveRemotePort + 52). TesterAutoRstDrop is alive while the first DUT SYN is
    // emitted, so the tester kernel's auto-RST to it is dropped and cannot kill the DUT's
    // SYN-SENT before the FIN arrives. When the stimulus returns it dies; the next DUT SYN
    // retransmit (Linux base RTO 1 s) draws a tester RST and the DUT goes SYN-SENT -> CLOSED
    // silently (no DUT egress on that path), so the absence guard stays satisfied. A bare FIN (no
    // ACK) is silently dropped in SYN-SENT; the absence guard tolerates DUT SYN retransmits
    // (is_dut_syn is excluded from its fail predicate).
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kLocalPort = kBasicsActiveLocalPort + kTcpFlagsProcessing08LocalOffset;
        constexpr std::uint16_t kRemotePort =
            kBasicsActiveRemotePort + kTcpFlagsProcessing08LocalOffset;

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        // Non-establishing active OPEN: fire the SYN and (on the opcode non-blocking worker)
        // return with the socket in SYN-SENT. The handle is unused: the case observes the DUT
        // SYN on the wire and the absence of any response to the bare FIN below.
        (void)driveSeamSynSentOpen(ctx.dut, cfg, kLocalPort, kRemotePort);
        cases::emitBareFin(cfg, ctx.iface, kRemotePort, kLocalPort);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08It3SM, tcp_flags_processing_08_it3)
