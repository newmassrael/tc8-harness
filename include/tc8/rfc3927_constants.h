#pragma once

#include <cstdint>

// RFC 3927 (Dynamic Configuration of IPv4 Link-Local Addresses) shared
// spec constants. Both the tc8-dut firmware and the tc8-harness binary
// consume these — the DUT to drive the protocol's runtime behaviour,
// the harness to assert that behaviour at the wire level. A single
// header ensures the two stay in lock-step; SSOT is mandatory because
// §4.5.6.2 _14 reads pcap from the harness against tc8-dut's emit
// count to assert the silence window — a value mismatch silently
// breaks the assertion.
//
// Live in `include/tc8/` (not `dut/` or `src/`) so the cross-built
// target ECU image and the host-built test harness see the same
// header on the same include path. Add new RFC 3927 constants here as
// future §4.5 sessions land — single import surface for the spec.

namespace tc8::rfc3927 {

// MAX_CONFLICTS — RFC 3927 §2.2.1. Once the host has experienced this
// many consecutive probing-window conflicts, it MUST limit the rate
// at which it probes for new addresses to no more than one new
// address per RATE_LIMIT_INTERVAL.
inline constexpr std::uint32_t kMaxConflicts = 10;

// RATE_LIMIT_INTERVAL — RFC 3927 §2.2.1. Default silence window
// (milliseconds) the host enforces between probe attempts after
// MAX_CONFLICTS is reached. Spec-fixed at 60 seconds; the harness's
// fast envelope overrides per-case for SCXML deadline fit (see
// `tc8::sce::linklocal::kFastRateLimitMs`).
inline constexpr std::uint16_t kRateLimitIntervalMs = 60000;

}  // namespace tc8::rfc3927
