#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace tc8::dut {

// Availability-gated request buffer: the policy that makes a one-shot SOME/IP
// Request timing-robust without the caller sequencing discovery. On submit it
// queries availability and either sends the Request immediately (the service is
// already available) or PARKS it keyed by (service, instance); parked Requests are
// flushed in submission order when onAvailable() fires for that key.
//
// This is PURE POLICY — vsomeip-free and lock-free. The availability query AND the
// send are injected (std::function), so the whole send-now-vs-park DECISION is
// owned here and unit-tested hermetically with a fake availability source and a
// recording sender; VsomeipEtsClientControl keeps only the vsomeip bindings
// (is_available / app_->send) and the mutex. The owner serialises all calls under
// its own mutex (both injected callables run under it, exactly where the inline
// app_->is_available / app_->send used to). The Request type is a template
// parameter so the test drives a plain payload.
template <class Request>
class PendingRequests {
public:
    using Key = std::pair<std::uint16_t, std::uint16_t>;
    using AvailabilityQuery = std::function<bool(std::uint16_t, std::uint16_t)>;
    using Sender = std::function<void(const Request&)>;

    PendingRequests(AvailabilityQuery is_available, Sender send)
        : is_available_(std::move(is_available)), send_(std::move(send)) {}

    // Send `request` now if (service, instance) is already available, otherwise
    // park it for onAvailable(service, instance).
    void submit(std::uint16_t service, std::uint16_t instance, Request request) {
        if (is_available_(service, instance)) {
            send_(request);
        } else {
            pending_[{service, instance}].push_back(std::move(request));
        }
    }

    // Send every Request parked for (service, instance), in submission order, then
    // drop the queue. A no-op when nothing was parked for that key.
    void onAvailable(std::uint16_t service, std::uint16_t instance) {
        const auto it = pending_.find({service, instance});
        if (it == pending_.end()) {
            return;
        }
        for (const auto& request : it->second) {
            send_(request);
        }
        pending_.erase(it);
    }

private:
    AvailabilityQuery is_available_;
    Sender send_;
    std::map<Key, std::vector<Request>> pending_;
};

}  // namespace tc8::dut
