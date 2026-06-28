#include "ets_event_sink.h"

#include <cstdio>
#include <set>
#include <utility>

#include <vsomeip/vsomeip.hpp>

namespace tc8::dut {
namespace {

// IEtsEventSink over a live vsomeip::application, scoped to one service/instance.
// offer_event / notify / register_message_handler all run on the SAME application
// the CommonAPI ETS service uses (obtained by name in makeEtsEventSink), so the
// OEM event surface adds to the existing offer with no second routing client.
class VsomeipEtsEventSink : public IEtsEventSink {
public:
    VsomeipEtsEventSink(std::shared_ptr<vsomeip::application> app,
                        vsomeip::service_t service, vsomeip::instance_t instance)
        : app_(std::move(app)), service_(service), instance_(instance) {}

    // Withdraw everything this sink registered on the shared application BEFORE it
    // is destroyed, so a queued inbound request cannot invoke a handler that
    // captured a now-dangling reference (the OEM handler typically captures the
    // sink to notify()). This makes the lifetime contract real rather than
    // relying on the caller's destruction order. NOTE: the DUT currently hard-
    // exits via std::_Exit (dut_main.cpp), which skips this dtor — so today this
    // matters only for a future graceful shutdown; a callback already in flight on
    // a vsomeip thread at teardown is still a residual race that a full
    // application stop would have to close.
    ~VsomeipEtsEventSink() override {
        if (!app_) return;
        for (const auto m : registered_methods_) {
            app_->unregister_message_handler(service_, instance_, m);
        }
        for (const auto e : offered_events_) {
            app_->stop_offer_event(service_, instance_, e);
        }
    }

    void offerEvent(std::uint16_t event_id,
                    const std::vector<std::uint16_t>& eventgroups) override {
        const std::set<vsomeip::eventgroup_t> egs(eventgroups.begin(), eventgroups.end());
        app_->offer_event(service_, instance_, event_id, egs,
                          vsomeip::event_type_e::ET_EVENT);
        offered_events_.push_back(event_id);
    }

    void notify(std::uint16_t event_id,
                const std::vector<std::uint8_t>& payload) override {
        app_->notify(service_, instance_, event_id,
                     vsomeip::runtime::get()->create_payload(payload));
    }

    void onMethod(std::uint16_t method_id,
                  std::function<void(const std::vector<std::uint8_t>&)> handler) override {
        registered_methods_.push_back(method_id);
        app_->register_message_handler(
            service_, instance_, method_id,
            [handler = std::move(handler)](const std::shared_ptr<vsomeip::message>& msg) {
                const auto pl = msg ? msg->get_payload() : nullptr;
                handler(payloadBytes(pl ? pl->get_data() : nullptr,
                                     pl ? pl->get_length() : 0));
            });
    }

private:
    std::shared_ptr<vsomeip::application> app_;
    vsomeip::service_t  service_;
    vsomeip::instance_t instance_;
    std::vector<vsomeip::event_t>  offered_events_;
    std::vector<vsomeip::method_t> registered_methods_;
};

// Null Object used when the vsomeip application cannot be found. Its no-ops keep
// the public DUT (whose default extension never touches the sink) running; an OEM
// extension that needed it sees no events offered, which the stderr log explains.
class NullEtsEventSink : public IEtsEventSink {
public:
    void offerEvent(std::uint16_t, const std::vector<std::uint16_t>&) override {}
    void notify(std::uint16_t, const std::vector<std::uint8_t>&) override {}
    void onMethod(std::uint16_t,
                  std::function<void(const std::vector<std::uint8_t>&)>) override {}
};

}  // namespace

std::unique_ptr<IEtsEventSink> makeEtsEventSink(const std::string& app_name,
                                                std::uint16_t service,
                                                std::uint16_t instance) {
    auto app = vsomeip::runtime::get()->get_application(app_name);
    if (!app) {
        std::fprintf(stderr,
                     "tc8-dut: ETS event sink - vsomeip application '%s' not found; "
                     "OEM event surface disabled\n",
                     app_name.c_str());
        return std::make_unique<NullEtsEventSink>();
    }
    return std::make_unique<VsomeipEtsEventSink>(std::move(app), service, instance);
}

}  // namespace tc8::dut
