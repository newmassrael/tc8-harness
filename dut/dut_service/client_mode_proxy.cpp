#include "client_mode_proxy.h"

#include <cstdio>

#include <CommonAPI/CommonAPI.hpp>

namespace tc8::dut {

namespace {

constexpr const char* kDomain   = "local";
constexpr const char* kInstance = "ETS3_TARGET";

}  // namespace

ClientModeProxyRunner::ClientModeProxyRunner() = default;

ClientModeProxyRunner::~ClientModeProxyRunner() { stop(); }

bool ClientModeProxyRunner::start() {
    std::lock_guard<std::mutex> lock(mu_);
    if (proxy_) {
        return true;
    }
    auto runtime = CommonAPI::Runtime::get();
    proxy_ = runtime->buildProxy<v1::org::tc8::ets3::ClientTargetProxy>(kDomain, kInstance);
    if (!proxy_) {
        std::fprintf(stderr, "client_mode_proxy: buildProxy failed\n");
        return false;
    }
    std::printf("tc8-dut: ets3 ClientTarget proxy built (domain=%s instance=%s)\n",
                kDomain, kInstance);
    return true;
}

bool ClientModeProxyRunner::subscribe() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!proxy_) {
        std::fprintf(stderr, "client_mode_proxy: subscribe() before start()\n");
        return false;
    }
    if (subscribed_.load()) {
        return true;
    }
    // Empty listener — ETS_097 only verifies the wire-side SubscribeEventgroup
    // + TCP-connect retry behaviour, so the actual event-payload callback is
    // not exercised. The presence of any subscriber is what makes vsomeip
    // emit SubscribeEventgroup with the TCP option and attempt the TCP
    // connect.
    subscription_token_ =
        proxy_->getTargetEventReliableEvent().subscribe([](uint8_t /*value*/) {});
    subscribed_.store(true);
    std::printf("tc8-dut: ets3 TargetEventReliable subscribed (token=%u)\n",
                subscription_token_);
    return true;
}

bool ClientModeProxyRunner::subscribeUdp() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!proxy_) {
        std::fprintf(stderr, "client_mode_proxy: subscribeUdp() before start()\n");
        return false;
    }
    if (subscribed_udp_.load()) {
        return true;
    }
    subscription_udp_token_ =
        proxy_->getTargetEventUnreliableEvent().subscribe([](uint8_t /*value*/) {});
    subscribed_udp_.store(true);
    std::printf("tc8-dut: ets3 TargetEventUnreliable subscribed (token=%u)\n",
                subscription_udp_token_);
    return true;
}

void ClientModeProxyRunner::stop() {
    std::lock_guard<std::mutex> lock(mu_);
    if (proxy_ && subscribed_.load()) {
        proxy_->getTargetEventReliableEvent().unsubscribe(subscription_token_);
        subscribed_.store(false);
    }
    if (proxy_ && subscribed_udp_.load()) {
        proxy_->getTargetEventUnreliableEvent().unsubscribe(subscription_udp_token_);
        subscribed_udp_.store(false);
    }
    proxy_.reset();
}

}  // namespace tc8::dut
