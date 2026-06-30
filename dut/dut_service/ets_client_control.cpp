#include "ets_client_control.h"

#include <cstdio>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "ets_vsomeip_app.h"  // acquireCommonApiApplication, messageBytes (SSOT)

namespace tc8::dut {
namespace {

// IEtsClientControl over a live vsomeip::application, the SAME application the
// CommonAPI ETS service uses (obtained by CommonAPI connection id in
// makeEtsClientControl). request_service / request_event / subscribe /
// unsubscribe / send all run on that one routing client — the DUT is both a
// server (the CommonAPI ETS offer) and, through this seam, a client, with no
// second application.
class VsomeipEtsClientControl : public IEtsClientControl {
public:
    explicit VsomeipEtsClientControl(std::shared_ptr<vsomeip::application> app)
        : app_(std::move(app)) {}

    // Withdraw everything this control opened BEFORE it is destroyed, so a tester
    // offering the service after teardown does not keep a stale subscription or
    // dangling handler alive on the shared application. The DUT currently
    // hard-exits via std::_Exit (dut_main.cpp), which skips this dtor — so today
    // this matters only for a future graceful shutdown, mirroring
    // VsomeipEtsEventSink. release_service is balanced here (once per unique
    // service ever requested), not per subscription, so a callMethod and a
    // subscribe to the same service do not release each other early.
    ~VsomeipEtsClientControl() override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& s : subscriptions_) {
            teardownLocked(s);
        }
        for (const auto& m : response_methods_) {
            app_->unregister_message_handler(m.service, m.instance, m.method);
        }
        for (const auto& e : status_eventgroups_) {
            app_->unregister_subscription_status_handler(e.service, e.instance,
                                                         e.eventgroup, vsomeip::ANY_EVENT);
        }
        // Withdraw control-method handlers, then stop offering the control
        // service(s) this control opened (the client-role receive surface).
        for (const auto& m : control_methods_) {
            app_->unregister_message_handler(m.service, m.instance, m.method);
        }
        for (const auto& s : offered_services_) {
            app_->stop_offer_service(s.first, s.second);
        }
        for (const auto& svc : requested_services_) {
            app_->release_service(svc.first, svc.second);
        }
    }

    void subscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                             std::uint16_t eventgroup,
                             const std::vector<std::uint16_t>& events, bool reliable,
                             std::uint8_t major) override {
        if (!app_) return;
        if (events.empty()) {
            // Precondition guard: with no requested event the eventgroup is never
            // registered, so vsomeip's discovery emits NO SubscribeEventgroup SD
            // entry — a silent no-op that would strand the verdict. Fail loud.
            std::fprintf(stderr,
                         "tc8-dut: ETS client control - subscribeEventgroup(eg=0x%04X) "
                         "with no events; no SubscribeEventgroup entry will be sent\n",
                         eventgroup);
            return;
        }
        const auto reliability = reliable ? vsomeip::reliability_type_e::RT_RELIABLE
                                          : vsomeip::reliability_type_e::RT_UNRELIABLE;
        const std::set<vsomeip::eventgroup_t> egs{eventgroup};

        std::lock_guard<std::mutex> lock(mutex_);
        requestServiceLocked(service, instance, major);
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

    void onSubscriptionStatus(std::uint16_t service, std::uint16_t instance,
                              std::uint16_t eventgroup,
                              std::function<void(bool)> handler) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        status_eventgroups_.push_back({service, instance, eventgroup});
        // ANY_EVENT: vsomeip tracks subscription status per event, but the
        // eventgroup-level "established" edge is what a duration anchor needs, so
        // catch any event's status (vsomeip's lookup falls back to ANY_EVENT).
        app_->register_subscription_status_handler(
            service, instance, eventgroup, vsomeip::ANY_EVENT,
            [handler = std::move(handler)](vsomeip::service_t, vsomeip::instance_t,
                                           vsomeip::eventgroup_t, vsomeip::event_t,
                                           std::uint16_t status) {
                // status 0x00 == SubscribeEventgroupAck (established); a non-zero
                // status is a Nack (not established).
                handler(status == 0);
            });
    }

    void offerControlMethod(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<void(const std::vector<std::uint8_t>&)> handler) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        // offer_service once per (service, instance) — a second control method on
        // the same control service reuses the offer.
        if (offered_services_.insert({service, instance}).second) {
            app_->offer_service(service, instance, major);
        }
        control_methods_.push_back({service, instance, method});
        app_->register_message_handler(
            service, instance, method,
            [handler = std::move(handler)](const std::shared_ptr<vsomeip::message>& msg) {
                if (!msg) return;
                handler(messageBytes(msg));  // fire-and-forget: no Response sent
            });
    }

    void callMethod(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    const std::vector<std::uint8_t>& payload, bool reliable,
                    std::uint8_t major) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        requestServiceLocked(service, instance, major);
        auto request = vsomeip::runtime::get()->create_request(reliable);
        request->set_service(service);
        request->set_instance(instance);
        request->set_method(method);
        request->set_interface_version(major);
        request->set_payload(vsomeip::runtime::get()->create_payload(payload));
        app_->send(request);
    }

    void onResponse(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)>
                        handler) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        response_methods_.push_back({service, instance, method});
        app_->register_message_handler(
            service, instance, method,
            [handler = std::move(handler)](const std::shared_ptr<vsomeip::message>& msg) {
                if (!msg) return;
                const auto type = msg->get_message_type();
                if (type != vsomeip::message_type_e::MT_RESPONSE &&
                    type != vsomeip::message_type_e::MT_ERROR) {
                    return;  // only client-side responses/errors are the reaction
                }
                handler(static_cast<std::uint8_t>(msg->get_return_code()),
                        messageBytes(msg));
            });
    }

private:
    struct Subscription {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t eventgroup;
        std::uint8_t major;
        std::vector<std::uint16_t> events;
    };
    struct ResponseMethod {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t method;
    };
    struct StatusEventgroup {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t eventgroup;
    };
    struct ControlMethod {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t method;
    };

    // request_service once per unique (service, instance); the matching
    // release_service runs in the dtor. Caller holds mutex_.
    void requestServiceLocked(std::uint16_t service, std::uint16_t instance,
                              std::uint8_t major) {
        if (requested_services_.insert({service, instance}).second) {
            app_->request_service(service, instance, major, vsomeip::ANY_MINOR);
        }
    }

    // unsubscribe (emits StopSubscribe) then release the events this subscription
    // requested. The service stays requested until the dtor. Caller holds mutex_.
    void teardownLocked(const Subscription& s) {
        app_->unsubscribe(s.service, s.instance, s.eventgroup);
        for (const auto event : s.events) {
            app_->release_event(s.service, s.instance, event);
        }
    }

    std::shared_ptr<vsomeip::application> app_;
    std::mutex mutex_;
    std::vector<Subscription> subscriptions_;
    std::vector<ResponseMethod> response_methods_;
    std::vector<StatusEventgroup> status_eventgroups_;
    std::vector<ControlMethod> control_methods_;
    std::set<std::pair<std::uint16_t, std::uint16_t>> offered_services_;
    std::set<std::pair<std::uint16_t, std::uint16_t>> requested_services_;
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
    void onSubscriptionStatus(std::uint16_t, std::uint16_t, std::uint16_t,
                              std::function<void(bool)>) override {}
    void offerControlMethod(std::uint16_t, std::uint16_t, std::uint16_t, std::uint8_t,
                            std::function<void(const std::vector<std::uint8_t>&)>) override {}
    void callMethod(std::uint16_t, std::uint16_t, std::uint16_t,
                    const std::vector<std::uint8_t>&, bool, std::uint8_t) override {}
    void onResponse(std::uint16_t, std::uint16_t, std::uint16_t,
                    std::function<void(std::uint8_t,
                                       const std::vector<std::uint8_t>&)>) override {}
};

}  // namespace

std::unique_ptr<IEtsClientControl> makeEtsClientControl() {
    // Shared application-keying contract (see acquireCommonApiApplication) — the
    // client surface rides the CommonAPI service's one routing client. The stderr
    // line on a miss preserves "OEM client surface disabled" for the boot-check.
    auto app = acquireCommonApiApplication("client control", "client surface");
    if (!app) {
        return std::make_unique<NullEtsClientControl>();
    }
    return std::make_unique<VsomeipEtsClientControl>(std::move(app));
}

}  // namespace tc8::dut
