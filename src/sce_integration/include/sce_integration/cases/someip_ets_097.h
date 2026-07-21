#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/tcp_server.h"

#include "someip_ets_097_sm.h"

namespace tc8::sce::cases {

using SomeipEts097SM = ::SCE::Generated::someip_ets_097::someip_ets_097;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_097 — SD_Client_restarts_tcp_connection. The
// DUT-as-client establishes a TCP connection to the tester-advertised
// reliable endpoint when it tries to subscribe to a TCP-reliable eventgroup;
// when the first attempt is refused, vsomeip must retry on the next
// OfferService Message per PRS_SOMEIPSD_00527.
//
// Pre-requisite firmware (gated by TC8_DUT_CLIENT_MODE=1):
//   * `clientServiceActivate` (Method 0x2F) builds the CommonAPI Proxy for
//     ets3 ClientTarget (SERVICE-ID 0xF4E9).
//   * `clientServiceSubscribeEventgroup` (Method 0x32) calls
//     `proxy->getTargetEventReliableEvent().subscribe(...)`. After this the
//     proxy registers interest; vsomeip emits SubscribeEventgroup carrying a
//     TCP IPv4 Endpoint Option AND attempts the TCP connect on the next
//     OfferService.
//   * vsomeip's `client_endpoint_impl.cpp:368-429` retries the TCP connect on
//     ECONNREFUSED. The verdict therefore relies on natural vsomeip behaviour
//     plus the wire-side observation that the second SYN succeeds.
//
// Stimulus chain:
//   1. emitFindServiceBoot — SERVICE-ID-1 server warm-up.
//   2. emitMethodRequestAfter(clientServiceActivate) — DUT proxy spawned.
//   3. Wait 800 ms for proxy buildProxy() to register.
//   4. emitMethodRequestAfter(clientServiceSubscribeEventgroup) — DUT calls
//      subscribe(). vsomeip queues the SD subscribe + TCP connect.
//   5. emitOfferServiceMulticastWithEndpoint(offer1, tester:30509, TCP) —
//      OfferService #1 with TCP endpoint, no listener up yet → DUT's first
//      SYN gets RST from the kernel (ECONNREFUSED at vsomeip).
//   6. Sleep 1500 ms — DUT vsomeip notices ECONNREFUSED + arms its retry timer.
//   7. openTcpListener(:30509) — flips the tester from "refuse" to "accept".
//   8. emitOfferServiceMulticastWithEndpoint(offer2, same endpoint) — second
//      OfferService triggers vsomeip's offer-driven reconnect.
//   9. acceptTcpOnce(timeout = 3 s) — sets `c.tcp_handshake_completed = 1`
//      when the second SYN completes the handshake.
//
// Verdict (3-state SCXML):
//   Phase 1 (listening_phase1, 6 s deadline): observe an OfferService for
//           SERVICE-ID-1 (tester-side server warm-up gate).
//   Phase 2 (listening_phase2_subscribe_seen, 12 s deadline): observe
//           SubscribeEventgroup from DUT for SERVICE-ID 0xF4E9 carrying a
//           TCP-l4 IPv4 Endpoint Option.
//   Phase 3 (listening_phase3_handshake, 6 s deadline): wait for the
//           stimulus chain to write `c.tcp_handshake_completed`. Cond on
//           the deadline reads the slot.
template <>
struct TestCaseTraits<cases::SomeipEts097SM> : SomeIpAnyBase<cases::SomeipEts097SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_097";
    static constexpr std::string_view kDescription =
        "DUT client restarts refused TCP connection on next OfferService";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::SomeIpRpcMessage activate{};
        activate.method_id    = 0x002F;       // clientServiceActivate
        activate.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;         // Fire&Forget
        activate.payload      = {0x00};       // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // Give the DUT proxy buildProxy() time to register before triggering
        // the subscribe — without this gap vsomeip rejects the subscribe
        // call as "service not yet known".
        std::this_thread::sleep_for(std::chrono::milliseconds(800));

        ::tc8::stimulus::SomeIpRpcMessage sub_trigger{};
        sub_trigger.method_id    = 0x0032;    // clientServiceSubscribeEventgroup
        sub_trigger.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;      // Fire&Forget
        // Args: UInt32 delay (0) + UInt32 duration (0). DUT-side override
        // ignores duration; delay is consumed by std::this_thread::sleep_for.
        sub_trigger.payload      = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, sub_trigger, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // OfferService #1 — TCP endpoint advertised but tester listener not
        // up yet. Kernel sends RST to any DUT SYN → vsomeip ECONNREFUSED.
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer1{};
        offer1.service.service_id    = 0xF4E9;   // ets3 SERVICE-ID
        offer1.service.instance_id   = 0x0001;
        offer1.service.major_version = 0x01;
        offer1.service.ttl           = 5;
        offer1.service.session_id    = 0x0001;
        // endpoint.ipv4_be left at 0 — the emitter auto-fills from `iface`.
        offer1.endpoint.port    = 30509;
        offer1.endpoint.l4proto = 0x06;          // TCP
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer1, std::chrono::milliseconds(500));

        // Give vsomeip's first connect attempt time to fire + fail.
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // Open the TCP listener and immediately emit OfferService #2; vsomeip
        // reacts to the offer by re-attempting the TCP connect, which now
        // completes against the live listener.
        const int listen_fd = ::tc8::stimulus::openTcpListener(iface, 30509);

        ::tc8::stimulus::OfferServiceWithEndpointTarget offer2 = offer1;
        offer2.service.session_id = 0x0002;
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            iface, offer2, std::chrono::milliseconds(200));

        if (listen_fd >= 0) {
            const int accepted =
                ::tc8::stimulus::acceptTcpOnce(listen_fd, std::chrono::milliseconds(3000));
            if (accepted == 1) {
                c.tcp_handshake_completed = 1;
            }
            ::close(listen_fd);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts097SM, someip_ets_097)
