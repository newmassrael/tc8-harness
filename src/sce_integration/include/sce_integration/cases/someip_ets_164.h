#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_observation.h"
#include "sce_integration/test_runner.h"
#include "tc8/someip/sd_wire_constants.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_164_sm.h"

namespace tc8::sce::cases {

using SomeipEts164SM = ::SCE::Generated::someip_ets_164::someip_ets_164;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_164 — SD_SuspendInterface. Tester drives a
// get / set / suspend / observe-StopOffer / wait / re-get cycle. Per
// PRS_SOMEIPSD_00356 / 00363 / 00364 / SIP_SD_811 the DUT shall:
//   - emit StopOfferService (ttl = 0) when suspendInterface is invoked,
//   - stay silent for the suspension duration,
//   - emit OfferService (ttl > 0) on resume,
//   - keep responding to field methods after resume.
//
// The DUT firmware (`dut_main.cpp:61` setSuspendCallback) implements this
// via runtime->unregisterService(...) → sleep(duration_ms) →
// registerService(...). suspend duration = 2000 ms here so the SCXML
// envelope stays bounded; trait re-issues getFieldA after the resume
// gate (Phase 4).
//
// Spec verdict-line reads "Value returned must not be the same as set by
// the Tester before the Suspension since after the suspension Time, the
// Interface is expected not to reset" — internally inconsistent. Lenient
// interpretation: post-resume getFieldA Response is accepted regardless
// of payload value (the conformance signal is "DUT field method works
// after resume", not the field value preservation).
template <>
struct TestCaseTraits<cases::SomeipEts164SM> : SomeIpAnyBase<cases::SomeipEts164SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_164";
    static constexpr std::string_view kDescription =
        "TestField get / set / suspendInterface / StopOffer / resume / get — DUT honors suspend cycle";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        // Marked before the boot, so an Offer the DUT sends while it runs counts.
        const ::tc8::sce::ObservationCursor booting = ctx.observer.mark();
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // The set must reach a service the DUT offers: the Offer phase 1 grades.
        if (!ctx.observer.awaitObservation(
                "dut_offer_before_set_field", booting,
                ::tc8::sce::dutSdFirstEntry(cfg.dut.ip, ::tc8::sd_entry_type::kOfferService,
                                            cfg.someip_dut.service_id),
                kOfferBound)) {
            return;
        }

        // 1. setFieldA(0x77) — Method 0x42, payload [0x77]. Phase 2
        // observes the Response.
        ::tc8::stimulus::SomeIpRpcMessage set{};
        set.method_id = 0x0042;
        set.payload   = {0x77};
        ::tc8::stimulus::emitMethodRequestAfter(ctx.iface, set, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // 2. suspendInterface(start=0, duration=2000) — Method 0x02
        // Fire&Forget, sent once phase 2 saw the set answered, so the
        // suspension cannot swallow a set the DUT had not answered yet.
        // Args 4-byte start + 4-byte duration BE.
        const ::tc8::stimulus::MethodEndpoint dest = ::tc8::sce::someipUdpMethodDest(cfg);
        const std::string iface(ctx.iface);
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3), [iface, dest]() {
                ::tc8::stimulus::SomeIpRpcMessage suspend{};
                suspend.method_id    = 0x0002;
                suspend.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;  // RequestNoReturn (Fire&Forget).
                suspend.payload      = {0x00, 0x00, 0x00, 0x00,   // start = 0
                                        0x00, 0x00, 0x07, 0xD0};  // duration = 2000 ms
                ::tc8::stimulus::MethodRequestTiming now{};
                now.pre_emit_wait = std::chrono::milliseconds(0);
                ::tc8::stimulus::emitMethodRequestAfter(iface, suspend, now, dest);
            });

        // 3. getFieldA again — Method 0x40, sent once the machine saw the
        // DUT offer the service again. Phase 4 observes the Response (any
        // payload).
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase4), [iface, dest]() {
                ::tc8::stimulus::SomeIpRpcMessage get{};
                get.method_id = 0x0040;
                ::tc8::stimulus::MethodRequestTiming now{};
                now.pre_emit_wait = std::chrono::milliseconds(0);
                ::tc8::stimulus::emitMethodRequestAfter(iface, get, now, dest);
            });
    }

    // How long the stimulus waits for the DUT's Offer before the set: the
    // phase-1 window, so the wait gives up when phase 1 would.
    static constexpr std::chrono::milliseconds kOfferBound{6000};
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts164SM, someip_ets_164)
