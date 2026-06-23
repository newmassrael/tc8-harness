#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_23_sm.h"

namespace tc8::sce::cases {

using Format23SM =
    ::SCE::Generated::someipsrv_format_23::someipsrv_format_23;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.23 — Service ID field of the Type 2 entry shall
// carry SdServerServiceID. Configured identity supplied at runtime
// via --expect service_id=<hex>.
template <>
struct TestCaseTraits<cases::Format23SM>
    : SomeIpSdOnlyBase<cases::Format23SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_23";
    static constexpr std::string_view kDescription =
        "Type 2 entry Service ID shall carry the configured SdServerServiceID";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // §5.1.5.1.23 exercises the Ack path: subscribe to eventgroup
        // 0x0002 (declared under TestEventUINT8 in dut/ets/ets.fdepl +
        // dut/dut_service/vsomeip.json) so DUT replies with
        // SubscribeEventgroupAck (TTL > 0) instead of Nack (TTL = 0).
        // The Type 2 entry-format invariants verified by FORMAT_19..28
        // are identical for Ack and Nack; running the Ack path
        // exercises the spec's primary case and the harness's
        // configured TTL value.
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, subscribe,
                                                     cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format23SM, someipsrv_format_23)
