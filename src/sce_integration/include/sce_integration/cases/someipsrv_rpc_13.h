#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_13_sm.h"

namespace tc8::sce::cases {

using Rpc13SM = ::SCE::Generated::someipsrv_rpc_13::someipsrv_rpc_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.13 — Different services share the same UDP port.
// Stimulus is FindService(any-service-id, any-instance) so vsomeip
// emits OfferService entries for every configured service. The
// shared-port vsomeip variant binds both 0xF4E7 and 0xF4E8 to UDP 30502.
template <>
struct TestCaseTraits<cases::Rpc13SM> : SomeIpSdOnlyBase<cases::Rpc13SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_13";
    static constexpr std::string_view kDescription =
        "Two distinct services advertise the same UDP port";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc13SM, someipsrv_rpc_13)
