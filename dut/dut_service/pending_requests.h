#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace tc8::dut {

// Availability-gated request buffer: the policy that makes a one-shot SOME/IP
// Request timing-robust without the caller sequencing discovery. A submitted
// Request is either sent immediately (the service is already available) or PARKED
// keyed by (service, instance) and flushed in submission order once the service
// becomes available.
//
// This is PURE POLICY — vsomeip-free and lock-free. It is split out of
// VsomeipEtsClientControl (which owns the vsomeip application and the mutex) so
// the "send now or hold until available" decision can be unit-tested hermetically
// with a recording sender, while the real control keeps only the vsomeip glue
// (is_available query, availability handler, locking). The owner serialises all
// calls under its own mutex and supplies the actual send via the constructor;
// the Request type is a template parameter so the test drives a plain payload.
template <class Request>
class PendingRequests {
public:
    using Key = std::pair<std::uint16_t, std::uint16_t>;
    using Sender = std::function<void(const Request&)>;

    explicit PendingRequests(Sender send) : send_(std::move(send)) {}

    // Send `request` now if `available`, otherwise park it for (service,
    // instance) to be flushed when the service becomes available.
    void submit(std::uint16_t service, std::uint16_t instance, bool available,
                Request request) {
        if (available) {
            send_(request);
        } else {
            pending_[{service, instance}].push_back(std::move(request));
        }
    }

    // Send every Request parked for (service, instance), in submission order,
    // then drop the queue. A no-op when nothing was parked for that key.
    void flush(std::uint16_t service, std::uint16_t instance) {
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
    Sender send_;
    std::map<Key, std::vector<Request>> pending_;
};

}  // namespace tc8::dut
