#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/tcp_accept_service.h"
#include "stimulus/tcp_server.h"
#include "stimulus/tx_observer.h"
#include "tc8/captured_event.h"
#include "tc8/protocol_frames/tcp_frame.h"
#include "tc8/test_defaults.h"

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
//   6. Await the tester kernel's RST to the DUT from :30509 — the refused first
//      connect, observed rather than assumed (bound ParamListenTime plus
//      ParamToleranceTime; a miss is an unperformed stimulus).
//   7. TcpAcceptService(:30509), adopted by the runner — flips the tester
//      from "refuse" to "accept" for the rest of the run; each accept sets
//      `c.tcp_handshake_completed = 1` and holds the connection.
//   8. emitOfferServiceMulticastWithEndpoint(offer2, same endpoint) — second
//      OfferService triggers vsomeip's offer-driven reconnect.
//
// Verdict (3-state SCXML):
//   Phase 1 (listening_phase1, 6 s deadline): observe an OfferService for
//           SERVICE-ID-1 (tester-side server warm-up gate).
//   Phase 2 (listening_phase2_subscribe_seen, 12 s deadline): observe
//           SubscribeEventgroup from DUT for SERVICE-ID 0xF4E9 carrying a
//           TCP-l4 IPv4 Endpoint Option.
//   Phase 3 (listening_phase3_handshake, 11 s window): the deadline reads
//           `c.tcp_handshake_completed`; still 0 is the DUT's silence where
//           it must reconnect (observed_quiescence over ParamListenTime).
template <>
struct TestCaseTraits<cases::SomeipEts097SM> : SomeIpAnyBase<cases::SomeipEts097SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_097";
    static constexpr std::string_view kDescription =
        "DUT client restarts refused TCP connection on next OfferService";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::SomeIpRpcMessage activate{};
        activate.method_id    = 0x002F;       // clientServiceActivate
        activate.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;         // Fire&Forget
        activate.payload      = {0x00};       // delay = 0
        ::tc8::stimulus::emitMethodRequestAfter(ctx.iface, activate, {}, ::tc8::sce::someipUdpMethodDest(cfg));

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
        ::tc8::stimulus::emitMethodRequestAfter(ctx.iface, sub_trigger, {}, ::tc8::sce::someipUdpMethodDest(cfg));

        // OfferService #1 — TCP endpoint advertised but tester listener not
        // up yet. Kernel sends RST to any DUT SYN → vsomeip ECONNREFUSED.
        ::tc8::stimulus::OfferServiceWithEndpointTarget offer1{};
        offer1.service.service_id    = 0xF4E9;   // ets3 SERVICE-ID
        offer1.service.instance_id   = 0x0001;
        offer1.service.major_version = 0x01;
        offer1.service.ttl           = 5;
        offer1.service.session_id    = 0x0001;
        // endpoint.ipv4_be left at 0 — the emitter auto-fills from `iface`.
        offer1.endpoint.port    = kTesterReliablePort;
        offer1.endpoint.l4proto = 0x06;          // TCP
        // Nothing serves the port yet, so the tester kernel answers the DUT's
        // SYN with an RST: the refusal the procedure restarts from.
        ::tc8::stimulus::reportTcpRefusal(ctx.iface, kTesterReliablePort);
        // Marked before the Offer, so a SYN the DUT sends while it is still
        // being emitted counts.
        const ::tc8::sce::ObservationCursor offered = ctx.observer.mark();
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            ctx.iface, offer1, std::chrono::milliseconds(500));

        // The case grades a RESTART, so it needs the first attempt refused
        // before it lets one succeed. Opening the listener after a fixed wait
        // would accept a DUT whose first SYN came later than the wait, and the
        // case would pass without a restart. So it waits for the RST that
        // refused the DUT's first connect (an absence of it is an unperformed
        // stimulus: the refusal the procedure depends on did not happen), the
        // DUT having its listen time to make that first attempt.
        const std::uint32_t dut_ip = cfg.dut.ip;
        const auto refused = ctx.observer.awaitObservation(
            "dut_first_connect_refused", offered,
            [dut_ip](const ::tc8::CapturedEvent &ev) {
                const auto *seg = std::get_if<::tc8::TcpFrame>(&ev);
                return seg != nullptr && seg->dst_ip == dut_ip &&
                       seg->src_port == kTesterReliablePort &&
                       (seg->flags & kTcpFlagRst) != 0U;
            },
            std::chrono::milliseconds(cfg.ixit.param_listen_time_ms) +
                ::tc8::defaults::kToleranceTime);
        if (!refused) {
            return;
        }

        // Open the TCP listener, then emit OfferService #2 at once; vsomeip
        // reacts to the offer by re-attempting the TCP connect, which now
        // completes against the live listener. The pass criteria ask for the
        // second SYN as the DUT's answer to ANOTHER OfferService, so the port
        // keeps refusing until that Offer goes out: the listener opens
        // immediately before it, with no wait in between, and a retry the DUT
        // makes on a timer of its own before the Offer is refused like the
        // first attempt. The runner owns the listener for the whole
        // run and accepts on every drain, so a connect at any point in the
        // window is heard: a bounded accept here would grant the DUT the bound
        // instead of the listen time, and a SYN after it would meet a closed
        // port. Each accepted connection is held, so the DUT's client
        // connection stays up as it would against a real server. A listener
        // that cannot be opened is recorded as an unperformed stimulus by the
        // primitive (stimulus/tx_observer.h, reportTxFailed).
        auto held = std::make_shared<std::vector<::tc8::stimulus::TcpConnection>>();
        auto listener = std::make_unique<::tc8::stimulus::TcpAcceptService>(
            ctx.iface, kTesterReliablePort, [&c, held](::tc8::stimulus::TcpConnection conn) {
                c.tcp_handshake_completed = 1;
                held->push_back(std::move(conn));
            });
        const bool listening = listener->ok();
        ctx.services.adoptService(std::move(listener));
        if (!listening) {
            return;
        }

        ::tc8::stimulus::OfferServiceWithEndpointTarget offer2 = offer1;
        offer2.service.session_id = 0x0002;
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            ctx.iface, offer2, std::chrono::milliseconds(0));
    }

    // The tester's reliable endpoint both Offers advertise.
    static constexpr std::uint16_t kTesterReliablePort = 30509;
    // RFC 793 RST control bit in TcpFrame::flags.
    static constexpr std::uint8_t kTcpFlagRst = 0x04U;
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts097SM, someip_ets_097)
