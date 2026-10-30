#pragma once

#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_08_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_08_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08It1SM =
    ::SCE::Generated::tcp_flags_processing_08_it1::tcp_flags_processing_08_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its three iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_PROCESSING_08",
    "A DUT in CLOSED, LISTEN or SYN-SENT does not process a FIN: CLOSED answers with an RST "
    "whose sequence number is zero, LISTEN and SYN-SENT stay silent (RFC 793 §3.9 p75 "
    "Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08It1SM>
    : TcpAnyBase<cases::TcpFlagsProcessing08It1SM> {
    // A closed port is the default state of a port nothing is bound to, so this iteration needs
    // nothing of the DUT's control interface and is measurable on any backend.
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_08_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_PROCESSING_08: a bare FIN sent to a CLOSED port is answered "
        "with an RST whose sequence number is zero";

    // Bare FIN to the closed DUT port. Same wire shape as the second iteration of
    // TCP_BASICS_04; RFC 793 §3.9 demands RST(seq=0).
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        using namespace ::tc8::sce::tcp;
        cases::emitBareFin(cfg, ctx.iface, kBasicsTesterPort, kBasicsClosedPort);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08It1SM, tcp_flags_processing_08_it1)
