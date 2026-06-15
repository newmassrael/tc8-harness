#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_11_sm.h"

namespace tc8::sce::cases {

using SdMessage11SM =
    ::SCE::Generated::someipsrv_sd_message_11::someipsrv_sd_message_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.11 — SubscribeEventgroup entry type (0x06) shall
// be used to subscribe to an eventgroup (TR_SOMEIP_00385). Verified
// by emitting a Subscribe and observing the DUT respond with a Type 2
// entry (0x07) echoing the configured Service ID.
template <>
struct TestCaseTraits<cases::SdMessage11SM>
    : SomeIpSdOnlyBase<cases::SdMessage11SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_11";
    static constexpr std::string_view kSpecSection = "5.1.5.3.11";
    static constexpr std::string_view kDescription =
        "Subscribe Eventgroup entry type (0x06) drives a Type 2 (0x07) reply";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface,
            ::tc8::stimulus::SubscribeEventgroupTarget{},
            cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage11SM, someipsrv_sd_message_11)
