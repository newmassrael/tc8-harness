#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_options_15_sm.h"

namespace tc8::sce::cases {

using Options15SM =
    ::SCE::Generated::someipsrv_options_15::someipsrv_options_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Spec deviation: spec body cites SERVICE-ID-2 (a TCP-only sibling
// service) but tc8-dut configures only SERVICE-ID-1 (0xF4E7) with
// BOTH transports enabled (reliable=TCP:30501 + unreliable=
// UDP:30502) per dut/dut_service/vsomeip.json. The OfferService SD
// therefore carries a TCP IPv4 Endpoint Option on the same service
// — verifying L4-Proto=0x06 + port=30501 on that option satisfies
// the spec invariant ("when port is TCP, L4-Proto = 0x06") without
// requiring a separate SERVICE-ID-2 vsomeip configuration. See
// project_someipsrv_options_coverage.md for the deviation log.
template <>
struct TestCaseTraits<cases::Options15SM>
    : SomeIpAnyBase<cases::Options15SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_15";
    static constexpr std::string_view kSpecSection = "5.1.5.5.15";
    static constexpr std::string_view kDescription =
        "Layer-4 Protocol field of the IPv4 Endpoint Option for TCP shall be 0x06";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Options15SM, someipsrv_options_15)
