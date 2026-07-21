#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_basic_02_sm.h"

namespace tc8::sce::cases {

using Basic02SM = ::SCE::Generated::someipsrv_basic_02::someipsrv_basic_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.5.2 — Service-Instance-IDs 0x0000 and 0xFFFF are
// reserved (0x0000 unallocated, 0xFFFF means "all instances" in
// FindService). Stimulus probes the DUT with a FindService whose
// instance_id is 0xFFFF (any-instance); the DUT must reply with an
// OfferService bearing a concrete instance_id, never the reserved
// values.
template <>
struct TestCaseTraits<cases::Basic02SM> : SomeIpSdOnlyBase<cases::Basic02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_BASIC_02";
    static constexpr std::string_view kDescription =
        "OfferService instance_id must not be reserved (0x0000 / 0xFFFF) "
        "in reply to a FindService with instance_id=0xFFFF";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // FindServiceTarget defaults to instance_id=0xFFFF (any-instance)
        // so the default ctor already encodes the BASIC_02 stimulus
        // shape; passing it explicitly self-documents the test intent.
        ::tc8::stimulus::FindServiceTarget target{};
        target.instance_id = 0xFFFF;
        ::tc8::stimulus::emitFindServiceBoot(iface, target, cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Basic02SM, someipsrv_basic_02)
