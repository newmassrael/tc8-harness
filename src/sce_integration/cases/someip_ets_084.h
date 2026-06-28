#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_084_sm.h"

namespace tc8::sce::cases {

using SomeipEts084SM = ::SCE::Generated::someip_ets_084::someip_ets_084;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_084 — ClientServiceDeactivate. After
// clientServiceActivate (Method 0x2F) + clientServiceSubscribeEventgroup
// (Method 0x32) + tester-side OfferService for ets3 (SERVICE-ID 0xF4E9),
// vsomeip on the DUT emits SubscribeEventgroup (Type 0x06, ttl > 0). Then
// clientServiceDeactivate (Method 0x30) triggers the proxy's stop() →
// vsomeip emits a SubscribeEventgroup entry with ttl == 0
// (StopSubscribeEventgroup per SD §4.2 / PRS_SOMEIPSD_00386).
//
// Wave 5-i continuation: reuses ets3 + ClientModeProxyRunner from ETS_097
// without any new firmware. The deactivate Method Request is fired via
// `IStimulusScheduler::scheduleAfterStateEntry` so timing tracks the SCXML
// phase advance instead of wall clock.
template <>
struct TestCaseTraits<cases::SomeipEts084SM> : SomeIpAnyBase<cases::SomeipEts084SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_084";
    static constexpr std::string_view kDescription =
        "Client mode deactivate — DUT emits StopSubscribeEventgroup for ets3";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::SomeIpRpcMessage activate{};
        activate.method_id    = 0x002F;       // clientServiceActivate
        activate.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;         // Fire&Forget
        activate.payload      = {0x00};       // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Proxy buildProxy() registration delay — same gap as ETS_097.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::SomeIpRpcMessage sub_trigger{};
        sub_trigger.method_id    = 0x0032;    // clientServiceSubscribeEventgroup
        sub_trigger.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;      // Fire&Forget
        // UInt32 delay (0) + UInt32 duration (0).
        sub_trigger.payload      = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, sub_trigger, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Open a tester-side TCP listener BEFORE emitting the offer.
        // For TCP-reliable eventgroups vsomeip on the DUT delays the wire
        // SD Subscribe until the TCP handshake completes; once an EOF
        // arrives on the connection it triggers ON_STOP_OFFER_SERVICE
        // before the queued Subscribe is serialised. Therefore the
        // accepted connection must be held open for the full SCXML walk —
        // a detached thread owns the fd and closes it after a generous
        // timeout that outlives the verdict deadline.
        const int listen_fd = ::tc8::stimulus::openTcpListener(iface, 30509);

        // Tester-side OfferService for ets3 with TCP endpoint advertised.
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer{};
        offer.service.service_id    = 0xF4E9;   // ets3 SERVICE-ID
        offer.service.instance_id   = 0x0001;
        offer.service.major_version = 0x01;
        offer.service.ttl           = 5;
        // Multicast SD session_id must be > emitFindServiceBoot's last
        // emit (sid=2, total_emits=2) — otherwise vsomeip's is_reboot
        // rule (old_rb=1 && new_rb=1 && old_sid (2) >= new_sid (1))
        // triggers expire_subscriptions on the tester sender and the
        // proxy is torn down before vsomeip emits the SD Subscribe.
        offer.service.session_id    = 0x0003;
        offer.endpoint.port         = 30509;
        offer.endpoint.l4proto      = 0x06;     // TCP (matches ets3.fdepl 0x000A reliable=true)
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer, std::chrono::milliseconds(500));

        // Inline accept that hands the accepted fd to a detached thread,
        // which holds the connection open for 30 s before closing both
        // accepted fd and listener. The SCXML walk runs in parallel after
        // kickStimulus returns; the thread's lifetime spans phases 2 + 3
        // so the DUT proxy stays "subscribed" until our deactivate emit
        // triggers the StopSubscribe.
        if (listen_fd >= 0) {
            std::thread([listen_fd]() {
                pollfd pfd{};
                pfd.fd     = listen_fd;
                pfd.events = POLLIN;
                const int rc = ::poll(&pfd, 1, 5000);
                int accepted = -1;
                if (rc > 0) {
                    accepted = ::accept(listen_fd, nullptr, nullptr);
                }
                // Hold the accepted fd open for 30 s — long enough to
                // outlive the SCXML walk (phase1 6 + phase2 12 + phase3
                // 10 = 28 s).
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (accepted >= 0) {
                    ::close(accepted);
                }
                ::close(listen_fd);
            }).detach();
        }

        // Schedule the clientServiceDeactivate emit on phase 3 entry —
        // i.e. immediately after the harness observes DUT's Subscribe
        // (Type 0x06, ttl > 0). Timing tracks SCXML, not wall clock.
        std::string iface_copy(iface);
        const auto deactivate_dest = ::tc8::sce::someipUdpMethodDest(cfg);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_stop_seen),
            [iface_copy, deactivate_dest]() {
                ::tc8::stimulus::SomeIpRpcMessage deactivate{};
                deactivate.method_id    = 0x0030;     // clientServiceDeactivate
                deactivate.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;       // Fire&Forget
                deactivate.payload      = {0x00};     // delay = 0
                ::tc8::stimulus::emitMethodRequestAfter(iface_copy, deactivate, {},
                                                        deactivate_dest);
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts084SM, someip_ets_084)
