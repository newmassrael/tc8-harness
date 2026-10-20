#pragma once

#include <cstdint>
#include <functional>
#include <set>
#include <utility>

namespace tc8::dut {

// The set of (service, instance) pairs a client has asked the stack to discover, and
// the rule for when a pair is asked for again.
//
// This is PURE POLICY, vsomeip-free and lock-free, in the shape of PendingRequests:
// what a request or a release DOES to the stack is injected (std::function), so the
// bookkeeping that decides whether to do it, in what order, and exactly once, is owned
// here and unit-tested hermetically with a recording fake. VsomeipEtsClientControl keeps
// the vsomeip bindings (register_availability_handler / request_service on the way in,
// unregister_availability_handler / release_service on the way out) and the mutex; the
// owner serialises all calls under its own mutex, as with PendingRequests.
//
// WHY A RELEASE EXISTS. vsomeip's request_service dedups per pair, and the discovery it
// starts (the Initial Wait Phase with its random draw, then the Find repetitions) runs
// once for as long as the pair stays requested. A client that must discover the same
// service AGAIN, with the fresh Initial Wait a new activation has, therefore has to let go
// of it first, and a pair it has let go of is requested anew by the next request().
// Without release() the second request of a pair is a no-op and the second discovery
// puts nothing on the wire.
//
// THE BALANCE. Every pair this holds is released exactly once: by release(), or by
// releaseAll() for what is still held when the client goes away. A pair released early is
// not held, so releaseAll() does not release it a second time, and a pair requested again
// after a release is held again and released again. That is the invariant the unit test
// pins; a release that leaves the pair in the set would double-release it at teardown.
class ServiceRequests {
public:
    using Key = std::pair<std::uint16_t, std::uint16_t>;
    // Ask the stack to discover the pair at interface version `major`. Called only when
    // the pair is not held.
    using Requester = std::function<void(std::uint16_t service, std::uint16_t instance,
                                         std::uint8_t major)>;
    // Let go of the pair. Called only for a pair that is held, once per hold.
    using Releaser = std::function<void(std::uint16_t service, std::uint16_t instance)>;

    ServiceRequests(Requester request, Releaser release)
        : request_(std::move(request)), release_(std::move(release)) {}

    // Request the pair unless it is already held. The first request fixes `major` for as
    // long as the pair is held (the stack dedups); a repeat is ignored whatever its
    // `major`, as it always was.
    void request(std::uint16_t service, std::uint16_t instance, std::uint8_t major) {
        if (held_.insert({service, instance}).second) {
            request_(service, instance, major);
        }
    }

    // Let go of the pair if it is held, and forget it. A pair that is not held is not
    // released: there is nothing of ours to let go of, and releasing what another holder
    // requested would take it from them. Returns whether it was held.
    bool release(std::uint16_t service, std::uint16_t instance) {
        if (held_.erase({service, instance}) == 0) {
            return false;
        }
        release_(service, instance);
        return true;
    }

    // Let go of everything still held, for the owner's teardown.
    void releaseAll() {
        for (const Key& key : held_) {
            release_(key.first, key.second);
        }
        held_.clear();
    }

    bool holds(std::uint16_t service, std::uint16_t instance) const {
        return held_.count({service, instance}) != 0;
    }

private:
    Requester request_;
    Releaser release_;
    std::set<Key> held_;
};

}  // namespace tc8::dut
