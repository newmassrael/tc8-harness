#pragma once

#include <cstdint>
#include <initializer_list>
#include <string_view>

namespace tc8::sce {

// The requirements a liveness anchor exercises, as tags a case declares against
// (docs/verdict_policy.md Section 2.1, H1).
//
// An absence decides a verdict only if the DUT was able to answer through the
// window's end, and that is shown by an exchange after the window — the liveness
// anchor. Any answered anchor shows that, so the choice of anchor never makes a
// verdict unsound. What it decides is POWER: an anchor that runs through the
// requirement under test goes unanswered by a DUT that violates that requirement
// wholesale — a DUT whose ARP responder is broken fails an ARP anchor too — and the
// case can then only say inconclusive about the very DUT it exists to fail. A
// `_neg` is the sharp form: its fault suppresses the emission, and an anchor the
// fault also suppresses leaves the `_neg` unable to pass. So a case names the
// requirements its test purpose grades, each anchor names the requirements it
// exercises, and the harness prefers an anchor disjoint from the case's.
//
// The vocabulary is exactly what the anchors exercise and nothing more. A
// requirement no anchor exercises (TCP retransmission, SOME/IP subscription,
// dropping a malformed ARP Request) can never conflict with one, so naming it here
// would change no decision. A tag joins only with an anchor that exercises it.
enum class DutRequirement : std::uint32_t {
    // Answer a well-formed ARP Request for the DUT's own address (RFC 826).
    kArpRespond = 1u << 0,
    // Resolve a neighbour: emit a Request for it and use the Reply (RFC 826).
    kArpResolve = 1u << 1,
    // Accept a well-formed IPv4 datagram addressed to the DUT (RFC 791, RFC 1122
    // §3.2.1).
    kIpv4Receive = 1u << 2,
    // Answer an ICMP Echo Request (RFC 792, RFC 1122 §3.2.2.6).
    kIcmpEchoRespond = 1u << 3,
};

// A set of DutRequirement tags. A struct rather than a bare integer so that a
// misaligned positional CaseEntry initialiser cannot silently land another
// field's value here.
struct DutRequirements {
    std::uint32_t bits = 0;

    constexpr DutRequirements() = default;
    constexpr explicit DutRequirements(std::uint32_t b) : bits(b) {}
    constexpr DutRequirements(std::initializer_list<DutRequirement> tags) {
        for (const DutRequirement t : tags) {
            bits |= static_cast<std::uint32_t>(t);
        }
    }

    constexpr bool intersects(DutRequirements other) const { return (bits & other.bits) != 0; }
    constexpr int sharedWith(DutRequirements other) const {
        int n = 0;
        for (std::uint32_t b = bits & other.bits; b != 0; b &= b - 1) {
            ++n;
        }
        return n;
    }
    constexpr bool operator==(DutRequirements other) const { return bits == other.bits; }
    constexpr bool operator!=(DutRequirements other) const { return bits != other.bits; }
};

// The exchanges the harness can run after a window to show the DUT was live.
enum class LivenessAnchorKind : std::uint8_t {
    // Tester ARP Request for the DUT's address, answered by an ARP Reply. Exercises
    // no IP at all, so it is the anchor for every IP-layer case.
    kArpExchange,
    // Tester ICMP Echo Request to the DUT, answered by an Echo Reply. To answer, the
    // DUT receives an IPv4 datagram and resolves the tester's address.
    kIcmpEcho,
};

constexpr std::string_view livenessAnchorName(LivenessAnchorKind kind) {
    switch (kind) {
        case LivenessAnchorKind::kArpExchange: return "arp_exchange";
        case LivenessAnchorKind::kIcmpEcho: return "icmp_echo";
    }
    return "unknown";
}

constexpr DutRequirements exercisedBy(LivenessAnchorKind kind) {
    switch (kind) {
        case LivenessAnchorKind::kArpExchange: return {DutRequirement::kArpRespond};
        case LivenessAnchorKind::kIcmpEcho:
            return {DutRequirement::kIpv4Receive, DutRequirement::kIcmpEchoRespond,
                    DutRequirement::kArpResolve};
    }
    return DutRequirements{~std::uint32_t{0}};
}

// The requirements a case grades when neither it nor (for a `_neg`) its positive
// declares them: the broad reading of its family. ARP cases grade ARP, so every
// anchor shares a requirement with an undeclared ARP case — still sound, but a
// case that grades one ARP function narrows the set to it and so gains an anchor
// that DUT can still answer. IPv4 and ICMPv4 cases grade the IP layer, which the
// ARP anchor does not touch. Every other family grades a requirement above the
// anchors and shares nothing with either.
constexpr DutRequirements defaultRequirementsUnderTest(std::string_view case_id) {
    auto starts = [&](std::string_view prefix) {
        return case_id.size() >= prefix.size() && case_id.substr(0, prefix.size()) == prefix;
    };
    if (starts("ARP_")) {
        return {DutRequirement::kArpRespond, DutRequirement::kArpResolve};
    }
    if (starts("ICMPv4_")) {
        return {DutRequirement::kIpv4Receive, DutRequirement::kIcmpEchoRespond};
    }
    // `IPv4_AUTOCONF_*` grades link-local address configuration, which neither
    // anchor exercises; it falls through to the empty set below.
    if (starts("IPv4_") && !starts("IPv4_AUTOCONF_")) {
        return {DutRequirement::kIpv4Receive};
    }
    return {};
}

// The anchor kind sharing the fewest requirements with `under_test`, ties going
// to the kind that exercises less (the order below). There is always one: a
// shared requirement costs power, never soundness, so no case is left without an
// anchor.
constexpr LivenessAnchorKind selectLivenessAnchor(DutRequirements under_test) {
    LivenessAnchorKind best = LivenessAnchorKind::kArpExchange;
    int best_shared = under_test.sharedWith(exercisedBy(best));
    for (const LivenessAnchorKind kind : {LivenessAnchorKind::kIcmpEcho}) {
        const int shared = under_test.sharedWith(exercisedBy(kind));
        if (shared < best_shared) {
            best = kind;
            best_shared = shared;
        }
    }
    return best;
}

}  // namespace tc8::sce
