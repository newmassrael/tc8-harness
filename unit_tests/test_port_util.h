#pragma once

#include <cstdint>

// Fixed listen/bind ports for hermetic tests, and the one rule they must obey.
//
// A test that binds a FIXED port must pick it BELOW the Linux ephemeral range
// (net.ipv4.ip_local_port_range, 32768-60999 by default). Ports inside that range
// are the pool the kernel draws from when it auto-assigns a source port to any
// outbound socket — so a concurrent process (another ctest job, a developer's
// client, this repo's own utm_export_smoke consumer, whose client sockets take
// kernel-assigned source ports) can be holding the exact port a test is about to
// bind. The bind then fails, the test goes red, and nothing about the failure
// points at the real cause: it is a collision with an unrelated process, not a
// defect in the code under test. SO_REUSEADDR does not rescue this — it relaxes
// TCP TIME_WAIT and multicast, not a live conflicting bind.
//
// The failure is rare, non-deterministic and indistinguishable from a genuine
// regression, which is exactly the profile of a flake that costs more to diagnose
// than to prevent. Below the range the collision cannot happen at all: the kernel
// never hands these out on its own, so the only way a test port is taken is if
// something deliberately bound it.
//
// This is a rule, not a suggestion, so it is compiled rather than written down:
// pass every fixed test port through TC8_STATIC_ASSERT_TEST_PORT and a violation
// is a build error at the constant's definition.
//
// Ports that MODEL an ephemeral source (a simulated client's local port, a DUT's
// active-open source) are a different thing and legitimately live inside the
// range — they are wire values in a fixture, not ports this process binds and
// races for. Do not put those through this check.

namespace testutil {

// Low edge of the default Linux ephemeral range. A system may lower
// ip_local_port_range, which only widens the safe zone; the guard is a
// compile-time check against the documented default, so it stays a constant.
inline constexpr std::uint16_t kEphemeralRangeStart = 32768;

// A fixed test port is safe when the kernel will never auto-assign it. Ports
// below 1024 need privilege, so the usable band is [1024, 32768).
inline constexpr bool isSafeFixedTestPort(std::uint16_t port) {
    return port >= 1024 && port < kEphemeralRangeStart;
}

}  // namespace testutil

// Attach to every fixed listen/bind port constant in a test.
#define TC8_STATIC_ASSERT_TEST_PORT(port)                                              \
    static_assert(::testutil::isSafeFixedTestPort(port),                               \
                  #port " is not a safe fixed test port: it must be below the Linux "  \
                        "ephemeral range (32768) so the kernel cannot hand it to a "   \
                        "concurrent process as an auto-assigned source port, and at "  \
                        "or above 1024 so it needs no privilege")
