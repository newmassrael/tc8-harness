#pragma once

#include <cstdint>
#include <optional>

#include "tc8/net/op_status.h"

// IPv4 link-local autoconfiguration sub-interface of the Tier-2 DUT-control
// seam. Its own header for the same reason the DHCP one is: starting an
// autoconf state machine is not socket-shaped, and the ~60 case headers that
// need the vocabulary should not pull the socket sub-interfaces to get it.

namespace tc8::sce::linklocal {

// OpStartLLAutoconf envelope — the six RFC 3927 timing knobs plus the rate-limit
// interval, in the order the wire carries them.
//
// Lives at the seam rather than beside the stimulus helper that used to own it,
// because it is the vocabulary both the helper and every backend speak.
struct LinkLocalStartConfig {
    std::uint16_t dhcp_timeout_ms        = 0;
    std::uint16_t probe_wait_ms          = 0;
    std::uint16_t probe_min_ms           = 0;
    std::uint16_t probe_max_ms           = 0;
    std::uint16_t announce_wait_ms       = 0;
    std::uint16_t announce_interval_ms   = 0;
    std::uint16_t rate_limit_interval_ms = 0;

    // Fault injection, and deliberately an optional rather than a plain byte
    // defaulting to zero.
    //
    // The two requests are different opcodes with different wire sizes: the
    // plain start is 16 bytes, the fault-injecting variant repeats the same
    // timing knobs and appends one flavor byte, making 17. Deriving the choice
    // from "flavor != 0" would therefore be a hidden coupling AND would lose a
    // documented use — flavor 0 (kFlavorNone) on the fault opcode is how a
    // negative case proves its COMPLIANT branch is still live. Engaged means
    // "use the fault opcode, with this flavor, zero included"; disengaged means
    // the plain 16-byte request.
    std::optional<std::uint8_t> flavor{};

    // False when the 1.5 s pilot wait was already paid by an earlier call. A
    // tester-side delay, honoured by the caller rather than the backend.
    bool apply_initial_wait = true;
};

}  // namespace tc8::sce::linklocal

namespace tc8::sce {

// Make the DUT run IPv4 link-local autoconfiguration. Nothing on the wire can
// provoke this — the DUT starts probing because it was told to — so a case that
// needs it is only measurable on a backend providing this sub-interface.
class ILinkLocalControl {
public:
    virtual ~ILinkLocalControl() = default;

    // Start autoconf with `spec`'s envelope. true when the DUT accepted the
    // request; false means the ask did not happen, which is a non-conclusion
    // rather than a DUT verdict.
    virtual bool startAutoconf(const linklocal::LinkLocalStartConfig &spec) = 0;

    // Read back the address the DUT has COMMITTED to, in network byte order.
    // The one operation on this sub-interface that reads instead of changing,
    // and the reason it exists at all: §4.5.6.2's claim-condition cases have to
    // address the tester's ARP Request at whatever the DUT chose, and that value
    // exists nowhere but the DUT. Until 2026-09-25 the helper built the request
    // frame itself and sent it, which is what docs/tech-debt.md TD-21 recorded —
    // a path that bypassed this seam and with it the capability gate, so a
    // backend that cannot answer produced a TIMEOUT where an honest skip was
    // owed.
    //
    // Answers `net::OpStatus` rather than a bool so the three ways this fails
    // stay apart: `Unsupported` for a backend whose protocol has no such read
    // (the decline the gate turns into a skip), `Failed` for a transport or
    // malformed-reply failure, `Ok` with `addr_be` set otherwise. `addr_be` is
    // untouched on anything but `Ok`.
    //
    // ⚠ Pure virtual on purpose. A default returning `Unsupported` would let a
    // new backend inherit a silent decline, and a silent decline of a read is
    // indistinguishable from a DUT that has not committed yet.
    virtual ::tc8::net::OpStatus queryCommittedAddress(std::uint32_t &addr_be) = 0;
};

}  // namespace tc8::sce
