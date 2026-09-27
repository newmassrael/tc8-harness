#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tc8 {

// "This stimulus step has been APPLIED", placed in the captured frame stream at
// the position of the DUT's own acknowledgement of it.
//
// Why a position and not a moment. A case that asserts the ABSENCE of a DUT frame
// after a precondition — "no ARP Request once the static entry is installed" —
// must not grade what the DUT emitted while the precondition was being set up.
// Measured on the wire (the first run of the static-entry pair): removing the
// tester's entry made the DUT resolve the tester to answer that very request, and
// the case graded that ARP exchange as a failure of a step that had not happened
// yet. A timer cannot separate the two, because the only thing that marks the
// boundary is the acknowledgement, and the acknowledgement is a frame. So the
// marker is delivered exactly where that frame falls in capture order: every frame
// before it was emitted before the step took effect, every frame after it after.
//
// The frame itself stays withheld from the state machine (it is control-plane
// scaffolding); only its meaning is delivered, by NAME. The name is the stimulus's
// own stable identifier — the one `UnperformedStimulus` would record had the step
// failed — so the SCXML never reads the control channel's framing, and a second
// DUT-control backend adds its own matcher without any case changing.
//
// Flow: the backend that sends an awaited request registers a matcher for its
// acknowledgement BEFORE the send (`expect`), and withdraws it if the DUT says
// no (`withdraw`), so a refused step never produces a marker. The capture
// pipeline, on each control-plane frame it withholds, asks `take`; a match yields
// the name once and is consumed.
class StimulusMarkers {
public:
    using Matcher = std::function<bool(const std::uint8_t *frame, std::size_t len)>;

    /// Register the acknowledgement of stimulus `name`. Returns a token for
    /// `withdraw`.
    static std::uint64_t expect(std::string name, Matcher matches) {
        std::lock_guard<std::mutex> lk(mutex());
        const std::uint64_t token = ++lastToken();
        pending().push_back({token, std::move(name), std::move(matches)});
        return token;
    }

    /// Drop a registration whose step turned out not to be applied.
    static void withdraw(std::uint64_t token) {
        std::lock_guard<std::mutex> lk(mutex());
        auto &p = pending();
        for (auto it = p.begin(); it != p.end(); ++it) {
            if (it->token == token) {
                p.erase(it);
                return;
            }
        }
    }

    /// The name of the first registration `frame` acknowledges, consumed; nullopt
    /// when it acknowledges none.
    static std::optional<std::string> take(const std::uint8_t *frame, std::size_t len) {
        std::lock_guard<std::mutex> lk(mutex());
        auto &p = pending();
        for (auto it = p.begin(); it != p.end(); ++it) {
            if (it->matches(frame, len)) {
                std::string name = std::move(it->name);
                p.erase(it);
                return name;
            }
        }
        return std::nullopt;
    }

    /// Clear every registration. One case runs per harness invocation; this is for
    /// tests and any future in-process multi-case driver.
    static void reset() {
        std::lock_guard<std::mutex> lk(mutex());
        pending().clear();
    }

private:
    struct Pending {
        std::uint64_t token;
        std::string name;
        Matcher matches;
    };
    // Function-local statics, as UnperformedStimulus: header-only, one instance
    // across every TU, no static-init-order dependency.
    static std::vector<Pending> &pending() {
        static std::vector<Pending> v;
        return v;
    }
    static std::uint64_t &lastToken() {
        static std::uint64_t t = 0;
        return t;
    }
    static std::mutex &mutex() {
        static std::mutex m;
        return m;
    }
};

}  // namespace tc8
