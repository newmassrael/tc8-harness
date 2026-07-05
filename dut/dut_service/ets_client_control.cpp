#include "ets_client_control.h"

#include <atomic>
#include <cstdio>
#include <memory>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "env_flag.h"  // envFlagOn — SSOT for the DUT's boolean env gates
#include "ets_vsomeip_app.h"  // acquireCommonApiApplication, messageBytes (SSOT)
#include "pending_requests.h"  // availability-gated Request buffer (testable policy)
#include "response_correlation.h"  // Response<->Request session correlation policy

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
    // dangling handler alive on the shared application. release_service is balanced
    // here (once per unique service ever requested), not per subscription, so a
    // callMethod and a subscribe to the same service do not release each other early.
    //
    // Enqueued-callback safety: unregister_availability_handler (below) stops only
    // FUTURE dispatch — it does NOT drain a flushPending callback vsomeip already
    // enqueued on its routing thread, and mutex_ alone excludes only an in-progress
    // callback, not an enqueued-but-not-started one. So BEFORE any teardown, trip
    // the shared `live_` latch under its own lock: a not-yet-started availability
    // callback then sees alive == false and returns without touching the destroyed
    // mutex_/pending_, and one already past that check (holding live_->m) finishes
    // before this barrier acquires live_->m. live_ outlives this control via the
    // callback's strong copy, so the callback never dereferences a dead latch. This
    // closes the use-after-free window the DUT otherwise only dodges by std::_Exit
    // skipping the dtor (dut_main.cpp); a future graceful shutdown may still quiesce
    // the application for a clean stop, but no longer must, to keep this dtor safe.
    // Lock order is live_->m then mutex_ (the availability callback nests them that
    // way); the barrier releases live_->m before taking mutex_, so no deadlock.
    ~VsomeipEtsClientControl() override {
        if (!app_) return;
        {
            std::lock_guard<std::mutex> latch(live_->m);
            live_->alive = false;
        }
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
        for (const auto& svc : requested_services_) {
            app_->unregister_availability_handler(svc.first, svc.second);
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
        // Debounce vsomeip's per-event status into ONE eventgroup-level edge: the
        // shared `last` (-1 unknown / 0 not-established / 1 established) is swapped
        // atomically, so the consumer is invoked only on a real transition and
        // never repeatedly for the same state across the eventgroup's events.
        // ANY_EVENT catches any event's status (vsomeip's lookup falls back to it).
        auto last = std::make_shared<std::atomic<int>>(-1);
        app_->register_subscription_status_handler(
            service, instance, eventgroup, vsomeip::ANY_EVENT,
            [handler = std::move(handler), last](vsomeip::service_t, vsomeip::instance_t,
                                                 vsomeip::eventgroup_t, vsomeip::event_t,
                                                 std::uint16_t status) {
                // status 0x00 == SubscribeEventgroupAck (established); non-zero == Nack.
                const int now = (status == 0) ? 1 : 0;
                if (last->exchange(now) != now) {
                    handler(now == 1);  // fire only on a real transition
                }
            },
            // _is_selective = true: without it vsomeip's deliver_subscription_state
            // gates the Nack branch on this flag and never reports a rejection, so
            // the `established == false` edge would be dead.
            /*_is_selective=*/true);
    }

    void callMethod(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    const std::vector<std::uint8_t>& payload, bool reliable,
                    std::uint8_t major) override {
        callMethodImpl(service, instance, method, payload, reliable, major,
                       vsomeip::message_type_e::MT_REQUEST);
    }

    void callMethodNoReturn(std::uint16_t service, std::uint16_t instance,
                            std::uint16_t method, const std::vector<std::uint8_t>& payload,
                            bool reliable, std::uint8_t major) override {
        callMethodImpl(service, instance, method, payload, reliable, major,
                       vsomeip::message_type_e::MT_REQUEST_NO_RETURN);
    }

    void onResponse(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)>
                        handler) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        response_methods_.push_back({service, instance, method});
        // Capture the correlation policy by strong copy (not `this`): the handler
        // may fire on a vsomeip dispatch thread after this control is destroyed, and
        // the shared_ptr keeps the policy alive for that enqueued callback — the same
        // this-free discipline the availability path gets from the live_ latch.
        app_->register_message_handler(
            service, instance, method,
            [service, instance, method, correlation = correlation_,
             handler = std::move(handler)](const std::shared_ptr<vsomeip::message>& msg) {
                if (!msg) return;
                const auto type = msg->get_message_type();
                if (type != vsomeip::message_type_e::MT_RESPONSE &&
                    type != vsomeip::message_type_e::MT_ERROR) {
                    return;  // only client-side responses/errors are the reaction
                }
                // Drop a Response/Error that does not correlate to a Request the DUT
                // actually sent: vsomeip delivers it here purely on the (service,
                // instance, method) match, but the proxy behaviour we model drops a
                // reply with an unknown Session ID (no pending call) OR a wrong
                // Interface Version (major mismatch), so the pending call times out.
                // Restores that on the raw client (see response_correlation.h / TD-15).
                if (!correlation->acceptResponse({service, instance, method},
                                                 msg->get_session(),
                                                 msg->get_interface_version())) {
                    return;
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

    // Liveness latch shared (by strong copy) with the async availability callbacks.
    // Heap-allocated so it outlives this control while vsomeip still holds an
    // enqueued callback's bound copy; the dtor trips `alive` under `m` as its
    // teardown barrier (see the dtor + requestServiceLocked).
    struct Liveness {
        std::mutex m;
        bool alive = true;
    };

    // Shared body for callMethod (MT_REQUEST) and callMethodNoReturn
    // (MT_REQUEST_NO_RETURN): build the Request, FIX its message type, and submit it
    // through the availability gate. The type is set before submit, so a Request
    // parked for a not-yet-available service flushes later with the right type.
    void callMethodImpl(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                        const std::vector<std::uint8_t>& payload, bool reliable,
                        std::uint8_t major, vsomeip::message_type_e message_type) {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        requestServiceLocked(service, instance, major);
        auto request = vsomeip::runtime::get()->create_request(reliable);
        // create_request defaults to MT_REQUEST; set the type explicitly so F&F
        // (MT_REQUEST_NO_RETURN) is a one-value difference and the REQUEST path stays
        // byte-identical on the wire.
        request->set_message_type(message_type);
        request->set_service(service);
        request->set_instance(instance);
        request->set_method(method);
        request->set_interface_version(major);
        request->set_payload(vsomeip::runtime::get()->create_payload(payload));
        // vsomeip DROPS (does not queue) a send to a not-yet-available service, and
        // request_service only STARTS the SD FindService — the OfferService is a
        // round trip away. pending_.submit() queries availability (the injected
        // app_->is_available) and either sends inline or PARKS the Request for the
        // availability handler (registered in requestServiceLocked) to flush on
        // ON_AVAILABLE.
        //
        // DEADLOCK-SAFE because vsomeip dispatches availability handlers
        // ASYNCHRONOUSLY (enqueued to its routing/dispatch thread, never invoked
        // inline) — so flushPending() never re-enters mutex_ on the thread already
        // holding it here; it just blocks until this call releases. NO STRAND:
        // submit's availability query AND its park both run under mutex_ (held
        // here), and flushPending() takes the same mutex_, so an availability edge
        // racing this call either dispatches its flush before the submit (which then
        // reads available and sends inline) or serialises after it (and drains what
        // we parked). ★Held Requests flush in call order, but a LATER call that finds
        // the service available sends inline before a still-parked earlier one
        // flushes — global FIFO across parked+immediate is NOT guaranteed (the
        // documented use is one-shot-per-trigger, so this is benign).
        pending_.submit(service, instance, std::move(request));
    }

    // request_service once per unique (service, instance); the matching
    // release_service runs in the dtor. Registers the availability handler that
    // flushes callMethod()'s parked Requests BEFORE request_service, so the first
    // OfferService cannot outrun it. The handler runs on a vsomeip routing thread;
    // it captures `this` AND a strong copy of the `live_` latch, and touches this
    // control's members only while holding live_->m with alive still true — so the
    // dtor's barrier turns a post-teardown callback into a no-op instead of a
    // use-after-free (see the dtor). The latch (not unregister_availability_handler,
    // which stops only future dispatch) is what closes the enqueued-callback window.
    // Caller holds mutex_.
    void requestServiceLocked(std::uint16_t service, std::uint16_t instance,
                              std::uint8_t major) {
        if (requested_services_.insert({service, instance}).second) {
            app_->register_availability_handler(
                service, instance,
                [this, live = live_](vsomeip::service_t s, vsomeip::instance_t i,
                                     bool available) {
                    if (!available) return;
                    std::lock_guard<std::mutex> latch(live->m);
                    if (!live->alive) return;  // control torn down — skip the flush
                    flushPending(s, i);
                });
            app_->request_service(service, instance, major, vsomeip::ANY_MINOR);
        }
    }

    // Flush callMethod()'s Requests parked for (service, instance) now that the
    // service is available. Runs on a vsomeip routing thread; takes mutex_ to
    // serialise with callMethod()'s submit (PendingRequests itself is lock-free).
    void flushPending(std::uint16_t service, std::uint16_t instance) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.onAvailable(service, instance);
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
    // Tripped by the dtor (under its own lock) before teardown so an enqueued
    // availability callback skips flushPending instead of touching destroyed
    // members; shared by strong copy with that callback. See requestServiceLocked.
    std::shared_ptr<Liveness> live_{std::make_shared<Liveness>()};
    std::vector<Subscription> subscriptions_;
    std::vector<ResponseMethod> response_methods_;
    std::vector<StatusEventgroup> status_eventgroups_;
    std::set<std::pair<std::uint16_t, std::uint16_t>> requested_services_;
    // Response<->Request session correlation, shared by strong copy with each
    // onResponse handler (which may outlive this control). recordRequest() runs
    // here on the send path; acceptResponse() runs on a vsomeip dispatch thread.
    // Strict interface-version correlation is an opt-in gate, read from the env
    // once at construction: OFF by default (stock proxy behaviour), ON for the
    // conformance profile that requires ignoring a wrong-Interface-Version
    // Response. The env read lives here (not in the pure policy) so the class stays
    // vsomeip- and environment-free.
    std::shared_ptr<ResponseCorrelation> correlation_{std::make_shared<ResponseCorrelation>(
        envFlagOn("TC8_DUT_STRICT_RESPONSE_INTERFACE_VERSION"))};
    // Requests callMethod() received while the service was not yet available,
    // flushed in submission order on ON_AVAILABLE. The injected availability query
    // and sender bind to the vsomeip application and run under mutex_, exactly where
    // the inline app_->is_available() / app_->send() used to. The sender records
    // each sent MT_REQUEST's vsomeip-assigned Session ID so a later Response is
    // matched to it — this is the one send choke point both the inline and the
    // parked-then-flushed paths pass through, so the session is captured once.
    PendingRequests<std::shared_ptr<vsomeip::message>> pending_{
        [this](std::uint16_t service, std::uint16_t instance) {
            return app_->is_available(service, instance);
        },
        [this](const std::shared_ptr<vsomeip::message>& request) {
            if (request->get_message_type() == vsomeip::message_type_e::MT_REQUEST) {
                // Send and record the vsomeip-assigned Session ID atomically, so a
                // Response cannot be accepted before its session is recorded (the
                // send only enqueues, so holding the correlation lock across it is
                // deadlock-free). send() stamps the session before it returns.
                correlation_->recordSent(
                    {request->get_service(), request->get_instance(),
                     request->get_method()},
                    request->get_interface_version(),  // the Request's Major
                    [&] {
                        app_->send(request);
                        return request->get_session();
                    });
            } else {
                // Fire & Forget (MT_REQUEST_NO_RETURN): no Response to correlate.
                app_->send(request);
            }
        }};
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
    void callMethod(std::uint16_t, std::uint16_t, std::uint16_t,
                    const std::vector<std::uint8_t>&, bool, std::uint8_t) override {}
    void callMethodNoReturn(std::uint16_t, std::uint16_t, std::uint16_t,
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
