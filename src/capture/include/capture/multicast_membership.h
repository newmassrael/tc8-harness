#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace tc8::capture {

// Holds IGMP memberships for the multicast groups a run must be able to hear,
// for exactly as long as the capture that depends on them.
//
// WHY THE CAPTURE NEEDS THIS AT ALL
// ---------------------------------
// The harness observes the wire passively, through pcap. A passive capture
// emits no IGMP membership report, so a bridge that does IGMP snooping — a
// wireless AP, or any managed switch with snooping enabled — has no reason to
// forward a group towards this interface and prunes it one hop short of the
// capture. Nothing downstream can detect that afterwards: the frames never
// reach the interface, so they are dropped by no ring, truncated by no snaplen,
// and every completeness counter reads clean. See tc8::CaptureStats for the
// measurement that established this.
//
// Joining is therefore not a convenience that makes more cases pass. It is the
// precondition that gives `recv == 0` its meaning: only once the group is held
// does "we captured nothing" license the conclusion "the DUT sent nothing",
// which is what every absence-asserting case rests on.
//
// The membership lives in the kernel for as long as the socket does, so this
// type is the socket's owner and the run's guarantee in the same object: while
// it is alive the groups are held, and when it dies they are released.
//
// Deliberately free of libpcap: the pcap handle and the membership are two
// independent kernel objects that happen to share a lifetime, and coupling them
// would put socket concerns inside a libpcap wrapper.
class MulticastMembership {
public:
    // Joins each dotted-quad group in `groups` on `iface`. Never throws and
    // never partially aborts: every group is attempted, and the ones the kernel
    // refused are reported through `failed()` so the caller can record an
    // honest partial result rather than an all-or-nothing guess.
    //
    // An empty `groups` yields an object that holds nothing and fails nothing —
    // the run needs no multicast to reason, so there is no precondition to
    // establish. That is a real state, not a degenerate one, and it is why
    // `failed()` being empty is the success condition rather than `held()`
    // being non-empty.
    static MulticastMembership join(std::string_view iface,
                                    const std::vector<std::string> &groups);

    // The operator declined the memberships (see `--no-multicast-membership`).
    //
    // This does NOT return an empty object. An empty one would say "this run
    // needed no multicast", which is a different claim and the one that would
    // let an absence-based pass through unexamined — turning the opt-out into a
    // silent restoration of the unsound behaviour. Declining records the groups
    // as needed-and-not-held, so the run still reports what it could not
    // establish and an absence-asserting case lands on inconclusive.
    static MulticastMembership declined(const std::vector<std::string> &groups);

    ~MulticastMembership();
    MulticastMembership(MulticastMembership &&) noexcept;
    MulticastMembership &operator=(MulticastMembership &&) noexcept;
    MulticastMembership(const MulticastMembership &) = delete;
    MulticastMembership &operator=(const MulticastMembership &) = delete;

    // Groups asked for, in the order requested.
    const std::vector<std::string> &requested() const {
        return requested_;
    }

    // Groups the kernel refused, each rendered as "group: reason" so a failure
    // reaches the trace with its cause attached rather than as a bare address
    // the reader has to re-diagnose.
    const std::vector<std::string> &failed() const {
        return failed_;
    }

    bool allHeld() const {
        return failed_.empty();
    }

private:
    MulticastMembership() = default;
    void release();

    std::vector<int> sockets_;
    std::vector<std::string> requested_;
    std::vector<std::string> failed_;
};

}  // namespace tc8::capture
