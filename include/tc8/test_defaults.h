#pragma once

#include <chrono>

// TC8 v3.0 §5.1.2.1 — default values for user-defined IUT configuration
// parameters. These are the values the spec itself publishes as defaults;
// deployments may override them per-DUT via the `<Param…>` placeholders
// referenced in the test procedures (§5.1.2.3).

namespace tc8::defaults {

// ANVL waits up to this interval for a packet after an event trigger.
inline constexpr std::chrono::seconds       kListenTime{10};

// Added to actual wait/listen times as slack when verifying timed behaviours.
inline constexpr std::chrono::seconds       kToleranceTime{1};

// Tolerance slack for events expressed in milliseconds.
inline constexpr std::chrono::milliseconds  kMillisecToleranceTime{100};

// Time the DUT is assumed to spend processing an incoming packet.
inline constexpr std::chrono::seconds       kProcessTime{2};

}  // namespace tc8::defaults
