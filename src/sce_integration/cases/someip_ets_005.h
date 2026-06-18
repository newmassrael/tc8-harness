#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_005_sm.h"

namespace tc8::sce::cases {

using SomeipEts005SM = ::SCE::Generated::someip_ets_005::someip_ets_005;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_005 — checkByteOrder. DUT reads UInt8 +
// UInt16 (both BE on the wire) and replies with their UInt32 sum (also
// BE). Stimulus UInt8 = 0x12, UInt16 = 0x3456; expected sum = 0x3468.
// Wire-byte assertion against the full 4-byte UInt32 response is the
// strongest byte-order check the spec body describes — it catches
// host-vs-network endianness drift on either the input or output side.
template <>
struct TestCaseTraits<cases::SomeipEts005SM> : SomeIpAnyBase<cases::SomeipEts005SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_005";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "checkByteOrder — DUT replies with UInt32 BE sum of UInt8+UInt16 BE inputs";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x001F;
        // CommonAPI default deployment serialises primitives back-to-back
        // with no alignment padding. UInt8 0x12 then UInt16 0x3456 BE.
        target.payload = {0x12, 0x34, 0x56};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    // Conformant checkByteOrder echo: UInt32 BE sum of 0x12 + 0x3456 = 0x3468.
    // Case-local SSOT for the positive assertion (cond reads
    // expected.payload_view()); --expect payload= overrides only for the
    // negative harness. Keeps the case self-contained across all drivers.
    static void applyExpectedDefaults(::tc8::SomeIpExpected& e) {
        ::tc8::setExpectedPayload(e, {0x00, 0x00, 0x34, 0x68});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts005SM, someip_ets_005)
