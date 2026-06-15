#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_26_sm.h"

namespace tc8::sce::cases {

using Format26SM =
    ::SCE::Generated::someipsrv_format_26::someipsrv_format_26;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.26 — TTL field of the Type 2 entry shall carry
// the configured timer TTL on a SubscribeEventgroupAck (Pass Criteria
// step 8 verifies "TTL set to <SERVICE-ID-1-TTL>"). The Synopsis
// carve-out for Stop / Nack entries (TTL = 0) is not exercised by
// this case — the trait stimulus subscribes to a configured
// eventgroup so vsomeip replies with an Ack carrying TTL > 0; a Nack
// (TTL = 0) lands fail_ttl, surfacing a vsomeip / configuration
// regression that the prior `or ttl == 0` accept-clause masked.
template <>
struct TestCaseTraits<cases::Format26SM>
    : SomeIpSdOnlyBase<cases::Format26SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_26";
    static constexpr std::string_view kSpecSection = "5.1.5.1.26";
    static constexpr std::string_view kDescription =
        "Type 2 entry TTL on a SubscribeEventgroupAck shall carry the configured TTL";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // §5.1.5.1.26 exercises the Ack path: subscribe to eventgroup
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

TC8_REGISTER_CASE(::tc8::sce::cases::Format26SM, someipsrv_format_26)
