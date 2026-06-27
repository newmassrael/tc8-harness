#pragma once

#include <atomic>
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

#include "someip_ets_081_sm.h"

namespace tc8::sce::cases {

using SomeipEts081SM = ::SCE::Generated::someip_ets_081::someip_ets_081;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_081 — ClientServiceActivate_Server_reboot. The
// DUT-as-client must detect a server reboot (signalled by an OfferService
// whose SD Session-ID is lower than the previous, both with Reboot=1) and
// renew its TCP connection by closing the existing endpoint and opening a
// fresh one (PRS_SOMEIPSD_00385).
//
// The verdict relies on the tester-side TCP listener counting handshakes:
// after offer #1 the DUT establishes conn #1; after the reboot offer #2
// (lower session_id) the DUT must establish conn #2. The detached accept
// thread sits on the listener and bumps `c.tcp_handshake_count` per accept,
// so the deadline cond reads `tcp_handshake_count >= 2` to assert renewal.
//
// Reuses ets3 + ClientModeProxyRunner from ETS_097 + ETS_084 with no new
// firmware. The reboot OfferService rides
// `IStimulusScheduler::scheduleAfterStateEntry` so its emit timing tracks
// the SCXML's phase advance instead of wall clock.
template <>
struct TestCaseTraits<cases::SomeipEts081SM> : SomeIpAnyBase<cases::SomeipEts081SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_081";
    static constexpr std::string_view kDescription =
        "Server-reboot recovery — DUT renews TCP after lower-sid OfferService";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::MethodRequestTarget activate{};
        activate.method_id    = 0x002F;       // clientServiceActivate
        activate.message_type = 0x01;         // Fire&Forget
        activate.payload      = {0x00};       // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Proxy buildProxy() registration delay — same gap as ETS_084/_097.
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::MethodRequestTarget sub_trigger{};
        sub_trigger.method_id    = 0x0032;    // clientServiceSubscribeEventgroup
        sub_trigger.message_type = 0x01;      // Fire&Forget
        // UInt32 delay (0) + UInt32 duration (0).
        sub_trigger.payload      = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, sub_trigger, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Open the tester-side TCP listener BEFORE emitting the offer.
        // For TCP-reliable eventgroups vsomeip on the DUT delays the wire
        // SD Subscribe until the TCP handshake completes; once an EOF
        // arrives on the connection it triggers ON_STOP_OFFER_SERVICE
        // before the queued Subscribe is serialised. Therefore the
        // accepted connections must outlive the SCXML walk — a detached
        // thread accepts up to two and holds them for 30 s.
        const int listen_fd = ::tc8::stimulus::openTcpListener(iface, 30509);

        // Tester-side OfferService #1 for ets3 with TCP endpoint.
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer1{};
        offer1.service.service_id    = 0xF4E9;   // ets3 SERVICE-ID
        offer1.service.instance_id   = 0x0001;
        offer1.service.major_version = 0x01;
        offer1.service.ttl           = 5;
        // sid=0x000A — high enough that the post-FindServiceBoot tracker
        // (rb=1, sid=2) does not trip is_reboot here (2 < 10), so vsomeip
        // processes offer #1 as a normal first-time offer.
        offer1.service.session_id    = 0x000A;
        offer1.endpoint.port         = 30509;
        offer1.endpoint.l4proto      = 0x06;     // TCP (matches ets3.fdepl)
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer1, std::chrono::milliseconds(500));

        // Detached accept thread: poll the listener, accept each inbound
        // handshake, increment c.tcp_handshake_count, hold all accepted
        // fds open for 30 s (outlives phase1 6 + phase2 12 + phase3 12 =
        // 30 s SCXML walk so neither connection EOFs mid-test).
        if (listen_fd >= 0) {
            Captured *cp = &c;
            std::thread([listen_fd, cp]() {
                int accepted_fds[4] = {-1, -1, -1, -1};
                int accepted_count  = 0;
                const auto deadline =
                    std::chrono::steady_clock::now() + std::chrono::seconds(30);

                while (accepted_count < 4) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= deadline) {
                        break;
                    }
                    const auto remaining = std::chrono::duration_cast<
                        std::chrono::milliseconds>(deadline - now).count();
                    pollfd pfd{};
                    pfd.fd     = listen_fd;
                    pfd.events = POLLIN;
                    const int rc = ::poll(&pfd, 1,
                                          static_cast<int>(remaining));
                    if (rc <= 0) {
                        break;
                    }
                    const int fd = ::accept(listen_fd, nullptr, nullptr);
                    if (fd < 0) {
                        break;
                    }
                    accepted_fds[accepted_count++] = fd;
                    cp->tcp_handshake_count =
                        static_cast<std::uint8_t>(accepted_count);
                }

                std::this_thread::sleep_for(std::chrono::seconds(30));
                for (int fd : accepted_fds) {
                    if (fd >= 0) {
                        ::close(fd);
                    }
                }
                ::close(listen_fd);
            }).detach();
        }

        // Schedule the reboot OfferService on phase 3 entry — i.e.
        // immediately after the harness observes DUT's first wire
        // Subscribe (TCP option). vsomeip's is_reboot rule (old_sid=10
        // >= new_sid=5, both rb=1) triggers expire_subscriptions on the
        // sender → DUT closes TCP #1 and re-attempts → tester accepts
        // conn #2 → tcp_handshake_count -> 2.
        std::string iface_copy(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_renewed_handshake),
            [iface_copy]() {
                ::tc8::stimulus::OfferServiceWithEndpointTarget offer2{};
                offer2.service.service_id    = 0xF4E9;
                offer2.service.instance_id   = 0x0001;
                offer2.service.major_version = 0x01;
                offer2.service.ttl           = 5;
                offer2.service.session_id    = 0x0005;  // < offer1.sid (0x0A) → reboot
                offer2.endpoint.port         = 30509;
                offer2.endpoint.l4proto      = 0x06;
                ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
                    iface_copy, offer2, std::chrono::milliseconds(0));
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts081SM, someip_ets_081)
