#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_21_sm.h"

namespace tc8::sce::cases {

using Format21SM =
    ::SCE::Generated::someipsrv_format_21::someipsrv_format_21;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.21 — Index First Option Run of the Type 2 entry
// shall reference the first option of this entry's first options run.
template <>
struct TestCaseTraits<cases::Format21SM>
    : SomeIpSdOnlyBase<cases::Format21SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_21";
    static constexpr std::string_view kDescription =
        "Type 2 entry Index First Option Run shall reference the first option of the first options run";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // §5.1.5.1.21 exercises the Ack path: subscribe to eventgroup
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

TC8_REGISTER_CASE(::tc8::sce::cases::Format21SM, someipsrv_format_21)
