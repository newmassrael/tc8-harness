#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
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
// when the first attempt is refused, the DUT must re-engage the connection
// with a second SYN as soon as it receives another OfferService
// (PRS_SOMEIPSD_00527).
//
// Pre-requisite firmware (gated by TC8_DUT_CLIENT_MODE=1):
//   * `clientServiceActivate` (Method 0x2F) builds the CommonAPI Proxy for
//     ets3 ClientTarget (SERVICE-ID 0xF4E9).
//   * `clientServiceSubscribeEventgroup` (Method 0x32) calls
//     `proxy->getTargetEventReliableEvent().subscribe(...)`. After this the
//     proxy registers interest; vsomeip emits SubscribeEventgroup carrying a
//     TCP IPv4 Endpoint Option AND attempts the TCP connect.
//
// WHAT THE CASE MUST TELL APART. The pass criteria ask for the second SYN as the
// DUT's answer to the Offer. A DUT may also retry a refused connect on a timer of
// its own (vsomeip's TCP client does, every 100 ms, without limit), and on the
// wire that retry is the same SYN. So before the second Offer the stimulus keeps
// refusing and watches what the DUT does unprompted, and the Offer goes out only
// where an answer to it can be told from a retry:
//   - QUIET: the DUT sends no SYN for a whole window W (ParamListenTime plus
//     ParamToleranceTime). Then no retry of its own is due, and a SYN after the
//     Offer is its answer. That last step is a test hypothesis, not an
//     observation: a DUT quiet for W does not retry on its own in the next W.
//   - STEADY RETRIES: three retries at a stable period P. The Offer goes out
//     half a period after the last one, so the DUT's own next retry is due P/2
//     later; a SYN before 3P/4 after the last retry (a quarter period of margin
//     for timer jitter) is its answer, and one at or after it is no evidence
//     either way. The hypothesis here: the period observed holds across the
//     Offer.
//   - Anything else (retries at an unsteady period) leaves no instant at which
//     the DUT's own retry is known not to come, so no post-Offer SYN can be
//     attributed.
// The SCXML grades the SYN against the instants this records, so the verdict
// stays the machine's: a SYN that cannot be attributed is inconclusive, never a
// pass, and no SYN at all within the window is the DUT's silence where it must
// answer (observed_quiescence).
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
//      connect, observed rather than assumed (bound W; a miss is an unperformed
//      stimulus).
//   7. Still refusing, watch the DUT's own retries (QUIET / STEADY / unsteady,
//      above) and record when its next retry could come.
//   8. TcpAcceptService(:30509), adopted by the runner, opened immediately
//      before offer2, so every retry before the Offer is refused like the first.
//   9. emitOfferServiceMulticastWithEndpoint(offer2, same endpoint), its send
//      instant recorded.
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

        const std::chrono::milliseconds window =
            std::chrono::milliseconds(cfg.ixit.param_listen_time_ms) + ::tc8::defaults::kToleranceTime;
        const std::uint32_t dut_ip = cfg.dut.ip;

        // The case grades a RESTART, so it needs the first attempt refused
        // before it lets one succeed. An absence of the refusal is an
        // unperformed stimulus: the refusal the procedure depends on did not
        // happen, the DUT having had W to make that first attempt.
        const auto refused = ctx.observer.awaitObservation(
            "dut_first_connect_refused", offered,
            [dut_ip](const ::tc8::CapturedEvent &ev) {
                const auto *seg = std::get_if<::tc8::TcpFrame>(&ev);
                return seg != nullptr && seg->dst_ip == dut_ip &&
                       seg->src_port == kTesterReliablePort &&
                       (seg->flags & kTcpFlagRst) != 0U;
            },
            window);
        if (!refused) {
            return;
        }

        // Still refusing: what does the DUT do unprompted? Each wait is an
        // observation either way (observeWithin), and each considers only SYNs
        // after the previous one, by capture time.
        std::int64_t last_us = std::get<::tc8::TcpFrame>(refused->view()).observed_ts_us;
        std::int64_t retries_us[kRetriesSampled] = {};
        int retries = 0;
        for (; retries < kRetriesSampled; ++retries) {
            const auto retry = ctx.observer.observeWithin(
                "dut_spontaneous_reconnect", offered, isDutReconnectSynAfter(dut_ip, last_us), window);
            if (!retry) {
                break;  // quiet for a whole window
            }
            last_us = std::get<::tc8::TcpFrame>(retry->view()).observed_ts_us;
            retries_us[retries] = last_us;
        }

        const RetryAttribution attribution = attributeRetries(retries_us, retries);
        c.spontaneous_retry_earliest_ts_us = attribution.retry_earliest_us;

        if (attribution.offer_at_us != 0) {
            const std::int64_t wait_us = attribution.offer_at_us - realtimeNowUs();
            if (wait_us > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(wait_us));
            }
        }

        // The listener opens immediately before the second Offer, so every retry
        // before the Offer is refused like the first attempt. The runner owns it
        // for the whole run and accepts on every drain, so the DUT's connection
        // completes at any point in the window and is held as a real server
        // would hold it. A listener that cannot be opened is recorded as an
        // unperformed stimulus by the primitive (stimulus/tx_observer.h).
        auto held = std::make_shared<std::vector<::tc8::stimulus::TcpConnection>>();
        auto listener = std::make_unique<::tc8::stimulus::TcpAcceptService>(
            ctx.iface, kTesterReliablePort,
            [held](::tc8::stimulus::TcpConnection conn) { held->push_back(std::move(conn)); });
        const bool listening = listener->ok();
        ctx.services.adoptService(std::move(listener));
        if (!listening) {
            return;
        }

        ::tc8::stimulus::OfferServiceWithEndpointTarget offer2 = offer1;
        offer2.service.session_id = 0x0002;
        c.reconnect_offer_ts_us = realtimeNowUs();
        if (attribution.unsteady) {
            // Every SYN after the Offer counts as possibly the DUT's own retry.
            c.spontaneous_retry_earliest_ts_us = c.reconnect_offer_ts_us;
        }
        ::tc8::stimulus::emitOfferServiceMulticastWithEndpoint(
            ctx.iface, offer2, std::chrono::milliseconds(0));
    }

    // A DUT SYN to the tester's reliable port raises dut_reconnect_syn, with its
    // arrival in `dut_syn_ts_us`; every other segment is ignored, and a SOME/IP
    // frame goes the base's way. A bare SYN to that port can only be the DUT's:
    // the tester never connects to its own listener.
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        if (const auto *seg = std::get_if<::tc8::TcpFrame>(&ev)) {
            if (isReconnectSyn(*seg)) {
                c.dut_syn_ts_us = seg->observed_ts_us;
                sm.raiseExternal(Event::Dut_reconnect_syn);
                sm.step();
            }
            return;
        }
        SomeIpAnyBase<cases::SomeipEts097SM>::dispatch(c, sm, ev);
    }

    // The tester's reliable endpoint both Offers advertise.
    static constexpr std::uint16_t kTesterReliablePort = 30509;
    // RFC 793 control bits in TcpFrame::flags.
    static constexpr std::uint8_t kTcpFlagSyn = 0x02U;
    static constexpr std::uint8_t kTcpFlagRst = 0x04U;
    static constexpr std::uint8_t kTcpFlagAck = 0x10U;
    // Retries watched before the second Offer: two periods, so their agreement
    // can be checked.
    static constexpr int kRetriesSampled = 3;

    // What the DUT's unprompted retries, observed while refused, allow the second
    // Offer to show. Pure, so the three outcomes are tested apart from the wire.
    struct RetryAttribution {
        std::int64_t offer_at_us = 0;        // when to send the Offer; 0 = now
        std::int64_t retry_earliest_us = 0;  // earliest own retry after it; 0 = none due
        bool unsteady = false;               // no instant is known free of an own retry
    };

    // `retries_us[0..count)`: the arrivals of the retries seen, `count` of at most
    // kRetriesSampled. Fewer than kRetriesSampled means the last wait saw a whole
    // quiet window (QUIET: none due). kRetriesSampled at a steady period P (the two
    // periods within a quarter of each other) puts the Offer half a period after
    // the last retry, with the DUT's own next one not before three quarters of a
    // period (STEADY: a quarter period of margin for timer jitter). Otherwise
    // UNSTEADY.
    static RetryAttribution attributeRetries(const std::int64_t *retries_us, int count) {
        RetryAttribution out;
        if (count < kRetriesSampled) {
            return out;
        }
        const std::int64_t first_period = retries_us[1] - retries_us[0];
        const std::int64_t second_period = retries_us[2] - retries_us[1];
        const std::int64_t last_us = retries_us[2];
        if (first_period > 0 && std::llabs(second_period - first_period) * 4 <= first_period) {
            out.offer_at_us = last_us + second_period / 2;
            out.retry_earliest_us = last_us + (second_period * 3) / 4;
        } else {
            out.unsteady = true;
        }
        return out;
    }

    static bool isReconnectSyn(const ::tc8::TcpFrame &seg) {
        return seg.dst_port == kTesterReliablePort && (seg.flags & kTcpFlagSyn) != 0U &&
               (seg.flags & kTcpFlagAck) == 0U;
    }

    static ::tc8::sce::ObservationPredicate isDutReconnectSynAfter(std::uint32_t dut_ip,
                                                                  std::int64_t after_us) {
        return [dut_ip, after_us](const ::tc8::CapturedEvent &ev) {
            const auto *seg = std::get_if<::tc8::TcpFrame>(&ev);
            return seg != nullptr && seg->src_ip == dut_ip && isReconnectSyn(*seg) &&
                   seg->observed_ts_us > after_us;
        };
    }

    // Now, in the capture's clock (CLOCK_REALTIME microseconds, the domain of
    // `observed_ts_us`), so instants the stimulus records compare with frames.
    static std::int64_t realtimeNowUs() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts097SM, someip_ets_097)
