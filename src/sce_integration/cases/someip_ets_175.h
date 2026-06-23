#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_175_sm.h"

namespace tc8::sce::cases {

using SomeipEts175SM = ::SCE::Generated::someip_ets_175::someip_ets_175;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_175 — SubscribeEventgroup with one IPv4
// Endpoint option (referenced) + one Configuration Option (Type 0x01,
// unreferenced). Per PRS_SOMEIPSD_00337 / 00387 / 00393 the DUT shall
// ignore the extra option and Ack the Subscribe.
template <>
struct TestCaseTraits<cases::SomeipEts175SM> : SomeIpAnyBase<cases::SomeipEts175SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_175";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with extra unreferenced Configuration Option — DUT Acks";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Configuration Option (SD TR_SOMEIP §7.4.6, Type 0x01). Body is a stream of
        // length-prefixed UTF-8 strings ending with a 0-length terminator;
        // a single 0x00 byte is the minimal "empty list" representation.
        params.extra_options.push_back({
            /*type=*/0x01,
            /*body=*/std::vector<std::uint8_t>{0x00},
            /*reserved=*/0
        });
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts175SM, someip_ets_175)
