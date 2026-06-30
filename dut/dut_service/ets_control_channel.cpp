#include "ets_control_channel.h"

#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "ets_vsomeip_app.h"  // acquireCommonApiApplication, messageBytes (SSOT)

namespace tc8::dut {
namespace {

// IEtsControlChannel over a live vsomeip::application — the SAME application the
// CommonAPI ETS service uses (obtained by CommonAPI connection id in
// makeEtsControlChannel). offer_service + register_message_handler run on that one
// routing client, so the inbound control surface shares it with the server sink
// and the client control (no second application).
class VsomeipEtsControlChannel : public IEtsControlChannel {
public:
    explicit VsomeipEtsControlChannel(std::shared_ptr<vsomeip::application> app)
        : app_(std::move(app)) {}

    // Withdraw the control-method handlers, then stop offering the control
    // service(s) this channel opened. The DUT hard-exits via std::_Exit
    // (dut_main.cpp), which skips this dtor — so today this matters only for a
    // future graceful shutdown, mirroring VsomeipEtsEventSink/ClientControl. The
    // offered major is replayed so stop_offer_service matches the offer exactly
    // (vsomeip emits the wire StopOfferService SD entry only on an exact match).
    ~VsomeipEtsControlChannel() override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& m : control_methods_) {
            app_->unregister_message_handler(m.service, m.instance, m.method);
        }
        for (const auto& [key, major] : offered_services_) {
            app_->stop_offer_service(key.first, key.second, major);
        }
    }

    void offerControlMethod(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<void(const std::vector<std::uint8_t>&)> handler) override {
        if (!app_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        // offer_service once per (service, instance) — a second control method on
        // the same control service reuses the offer. Remember the major so the dtor
        // can stop_offer_service with the exact (major) it offered.
        if (offered_services_.emplace(std::make_pair(service, instance), major).second) {
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

private:
    struct ControlMethod {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t method;
    };

    std::shared_ptr<vsomeip::application> app_;
    std::mutex mutex_;
    std::vector<ControlMethod> control_methods_;
    // (service, instance) -> offered major, so teardown replays the exact major.
    std::map<std::pair<std::uint16_t, std::uint16_t>, std::uint8_t> offered_services_;
};

// Null Object used when the vsomeip application cannot be found. Its no-op keeps
// the public DUT (whose default extension never touches the channel) running; an
// OEM extension that needed it sees no control service offered, which the stderr
// log from makeEtsControlChannel explains.
class NullEtsControlChannel : public IEtsControlChannel {
public:
    void offerControlMethod(std::uint16_t, std::uint16_t, std::uint16_t, std::uint8_t,
                            std::function<void(const std::vector<std::uint8_t>&)>) override {}
};

}  // namespace

std::unique_ptr<IEtsControlChannel> makeEtsControlChannel() {
    // Shared application-keying contract (see acquireCommonApiApplication) — the
    // control surface rides the CommonAPI service's one routing client. A distinct
    // surface string keeps its miss-log separate from the sink/client.
    auto app = acquireCommonApiApplication("control channel", "control surface");
    if (!app) {
        return std::make_unique<NullEtsControlChannel>();
    }
    return std::make_unique<VsomeipEtsControlChannel>(std::move(app));
}

}  // namespace tc8::dut
