#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

#include <v1/org/tc8/ets3/ClientTargetProxy.hpp>

namespace tc8::dut {

// CommonAPI Proxy-mode client runner for §5.1.6 SOMEIP_ETS_097
// (SD_Client_restarts_tcp_connection). Coexists with the raw-UDP
// `ClientModeRunner` (client_mode.h) — they are mutually exclusive, gated by
// the `TC8_DUT_CLIENT_MODE` env var inside `EtsImpl::clientServiceActivate`:
//
//   * TC8_DUT_CLIENT_MODE unset → raw-UDP runner (covers ETS_098..101).
//   * TC8_DUT_CLIENT_MODE=1     → this Proxy runner (covers ETS_097).
//
// The Proxy path delegates the entire SD/SubscribeEventgroup/TCP-retry chain
// to vsomeip's CommonAPI integration:
//   1. start() builds the proxy for ets3 ClientTarget (SERVICE-ID 0xF4E9).
//      vsomeip-internal SD client emits FindService and stays ready to
//      receive OfferService.
//   2. subscribe() calls `proxy->getTargetEventReliable().subscribe(...)`.
//      The first OfferService received causes vsomeip to emit
//      SubscribeEventgroup carrying a TCP IPv4 Endpoint Option (because
//      `SomeIpReliable = true` in ets3.fdepl). vsomeip then attempts the
//      TCP connect and, on ECONNREFUSED, auto-retries via
//      `client_endpoint_impl.cpp:368-429` (start_connect_timer →
//      wait_connect_cbk → reconnect on next OfferService).
//   3. stop() unsubscribes and releases the proxy.
//
// This runner therefore needs zero custom socket code, zero retry logic, and
// zero SD listener — every wire-shape ETS_097 verifies emerges naturally from
// vsomeip's existing client lifecycle.
class ClientModeProxyRunner {
public:
    ClientModeProxyRunner();
    ~ClientModeProxyRunner();

    ClientModeProxyRunner(const ClientModeProxyRunner&) = delete;
    ClientModeProxyRunner& operator=(const ClientModeProxyRunner&) = delete;

    // Builds the CommonAPI Proxy for ets3 ClientTarget if not already built.
    // Idempotent. Returns true on success / already running.
    bool start();

    // Calls subscribe() on the TCP-reliable target event. Idempotent — the
    // second call is a no-op so re-triggering the spec's "Subscribe attempt"
    // step does not crash or double-subscribe. Returns true if the call was
    // dispatched (proxy must be started first).
    bool subscribe();

    // §5.1.6 SOMEIP_ETS_082 companion to subscribe() — registers an empty
    // listener on the UDP-unreliable target event (eventgroup 0x000B in
    // ets3.fdepl). vsomeip then emits SubscribeEventgroup whose IPv4
    // Endpoint Option carries l4proto = 0x11 (UDP). Idempotent.
    bool subscribeUdp();

    // Releases the proxy + clears the subscription. Safe to call when not
    // started.
    void stop();

private:
    std::mutex                                                      mu_;
    std::shared_ptr<v1::org::tc8::ets3::ClientTargetProxy<>>        proxy_;
    std::atomic<bool>                                               subscribed_{false};
    uint32_t                                                        subscription_token_{0};
    std::atomic<bool>                                               subscribed_udp_{false};
    uint32_t                                                        subscription_udp_token_{0};
};

}  // namespace tc8::dut
