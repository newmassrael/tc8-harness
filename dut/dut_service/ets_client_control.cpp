#include "ets_client_control.h"

#include <cstdio>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include <CommonAPI/CommonAPI.hpp>
#include <vsomeip/vsomeip.hpp>

namespace tc8::dut {
namespace {

// IEtsClientControl over a live vsomeip::application, the SAME application the
// CommonAPI ETS service uses (obtained by CommonAPI connection id in
// makeEtsClientControl). request_service / request_event / subscribe /
// unsubscribe run on that one routing client — the DUT is both a server (the
// CommonAPI ETS offer) and, through this seam, a client, with no second
// application.
class VsomeipEtsClientControl : public IEtsClientControl {
public:
    explicit VsomeipEtsClientControl(std::shared_ptr<vsomeip::application> app)
        : app_(std::move(app)) {}

    // Withdraw every subscription this control opened BEFORE it is destroyed, so
    // a tester offering the service after teardown does not keep a stale
    // subscription alive on the shared application. The DUT currently hard-exits
    // via std::_Exit (dut_main.cpp), which skips this dtor — so today this matters
    // only for a future graceful shutdown, mirroring VsomeipEtsEventSink.
    ~VsomeipEtsClientControl() override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& s : subscriptions_) {
            teardownLocked(s);
        }
    }

    void subscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                             std::uint16_t eventgroup,
                             const std::vector<std::uint16_t>& events, bool reliable,
                             std::uint8_t major) override {
        if (!app_) return;
        const auto reliability = reliable ? vsomeip::reliability_type_e::RT_RELIABLE
                                          : vsomeip::reliability_type_e::RT_UNRELIABLE;
        const std::set<vsomeip::eventgroup_t> egs{eventgroup};

        std::lock_guard<std::mutex> lock(mutex_);
        app_->request_service(service, instance, major, vsomeip::ANY_MINOR);
        // Register every event of the eventgroup before subscribe(): vsomeip
        // needs the type/reliability of each to route notifications (see
        // request_event's header note), and a subscribe with no requested event
        // would not deliver the eventgroup's events.
        for (const auto event : events) {
            app_->request_event(service, instance, event, egs,
                                vsomeip::event_type_e::ET_EVENT, reliability);
        }
        app_->subscribe(service, instance, eventgroup, major);
        subscriptions_.push_back({service, instance, eventgroup, major, events});
    }

    void stopSubscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                                 std::uint16_t eventgroup) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = subscriptions_.begin(); it != subscriptions_.end(); ++it) {
            if (it->service == service && it->instance == instance &&
                it->eventgroup == eventgroup) {
                teardownLocked(*it);
                subscriptions_.erase(it);
                return;
            }
        }
    }

private:
    struct Subscription {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t eventgroup;
        std::uint8_t major;
        std::vector<std::uint16_t> events;
    };

    // unsubscribe (emits StopSubscribe) then release the events and the service
    // this subscription requested. Caller holds mutex_.
    void teardownLocked(const Subscription& s) {
        app_->unsubscribe(s.service, s.instance, s.eventgroup);
        for (const auto event : s.events) {
            app_->release_event(s.service, s.instance, event);
        }
        app_->release_service(s.service, s.instance);
    }

    std::shared_ptr<vsomeip::application> app_;
    std::mutex mutex_;
    std::vector<Subscription> subscriptions_;
};

// Null Object used when the vsomeip application cannot be found. Its no-ops keep
// the public DUT (whose default extension never touches the control) running; an
// OEM extension that needed it sees no subscribe emitted, which the stderr log
// from makeEtsClientControl explains.
class NullEtsClientControl : public IEtsClientControl {
public:
    void subscribeEventgroup(std::uint16_t, std::uint16_t, std::uint16_t,
                             const std::vector<std::uint16_t>&, bool,
                             std::uint8_t) override {}
    void stopSubscribeEventgroup(std::uint16_t, std::uint16_t, std::uint16_t) override {}
};

}  // namespace

std::unique_ptr<IEtsClientControl> makeEtsClientControl() {
    // Same application-keying contract as makeEtsEventSink: CommonAPI's default
    // connection creates the vsomeip application under CommonAPI::DEFAULT_CONNECTION_ID
    // (the empty string), which keys vsomeip's application map — NOT the display
    // name. Retrieve it by the connection id so the client surface shares the
    // CommonAPI service's one routing client.
    auto app = vsomeip::runtime::get()->get_application(CommonAPI::DEFAULT_CONNECTION_ID);
    if (!app) {
        std::fprintf(stderr,
                     "tc8-dut: ETS client control - CommonAPI vsomeip application "
                     "(default connection) not found; OEM client surface disabled\n");
        return std::make_unique<NullEtsClientControl>();
    }
    return std::make_unique<VsomeipEtsClientControl>(std::move(app));
}

}  // namespace tc8::dut
