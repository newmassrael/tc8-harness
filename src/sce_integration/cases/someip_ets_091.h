#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_091_sm.h"

namespace tc8::sce::cases {

using SomeipEts091SM = ::SCE::Generated::someip_ets_091::someip_ets_091;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_091 — SD_Check_OfferService_Request_ID_incrementation.
// The DUT's cyclic MULTICAST OfferService stream must carry strictly-increasing
// SD Session-IDs across iterations (PRS_SOMEIPSD_00154 / 00157 / 00355). Because
// the SD Session-ID is maintained per communication relation (PRS_SOMEIPSD_00160),
// both SCXML phases pin to the multicast SD destination
// (`captured.dst_ip == expected.sd_multicast_ip`) so the snapshotted
// `prev_sd_session_id` and the compared `session_id` come from the same counter.
// Phase 1 snapshots `prev_sd_session_id` on the first observed multicast
// OfferService; phase 2 asserts `session_id > prev_sd_session_id` on the next.
template <>
struct TestCaseTraits<cases::SomeipEts091SM> : SomeIpAnyBase<cases::SomeipEts091SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_091";
    static constexpr std::string_view kDescription =
        "Cyclic OfferService Session-IDs must strictly increment across iterations";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // FindServiceBoot warms up SD on the tester side and re-engages
        // the DUT's Repetition / Main Phase cadence — same envelope every
        // §5.1.6 ETS observation case uses. ETS_091's verdict only reads
        // session_id deltas, so no further stimulus is required. The Find
        // also provokes a unicast solicited OfferService whose Session-ID
        // is drawn from a separate per-relation counter; the SCXML multicast
        // cast guard excludes it so both phases compare within one relation.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts091SM, someip_ets_091)
