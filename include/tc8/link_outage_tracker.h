#pragma once

#include <cstdint>
#include <vector>

#include "tc8/capture_stats.h"  // LinkOutage

namespace tc8 {

// Turns successive observations of one capture source's link into the outage
// intervals CaptureStats::link_outages records. Pure: the caller reads the link
// (tc8::net::readLinkState) and the clock, so the bookkeeping is testable without
// an interface. An observation is "the link carries traffic" (administratively up
// AND carrier) or not; an interface whose state cannot be read carries nothing.
class LinkOutageTracker {
public:
    // One observation at `now_us` (CLOCK_REALTIME epoch microseconds).
    void observe(bool carries_traffic, std::int64_t now_us) {
        if (!carries_traffic && !down_) {
            down_ = true;
            outages_.push_back(LinkOutage{now_us, 0});
        } else if (carries_traffic && down_) {
            down_ = false;
            outages_.back().end_us = now_us;
        }
    }

    // Whether the last observation found the link down.
    bool down() const {
        return down_;
    }

    // Every outage so far; the last has `end_us` 0 while the link is still down.
    const std::vector<LinkOutage> &outages() const {
        return outages_;
    }

private:
    bool down_ = false;
    std::vector<LinkOutage> outages_;
};

}  // namespace tc8
