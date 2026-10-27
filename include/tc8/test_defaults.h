#pragma once

#include <chrono>

// TC8 v3.0 §5.1.2.1 — default values for user-defined IUT configuration
// parameters. These are the values the spec itself publishes as defaults;
// deployments may override them per-DUT via the `<Param…>` placeholders
// referenced in the test procedures (§5.1.2.3).

namespace tc8::defaults {

// <ParamListenTime>: the longest the tester waits for a packet after an event
// was triggered on the DUT. The procedures that say "Listens (up to
// <ParamListenTime>)" grant the DUT this long to answer, so it is the bound an
// absence in such a step is judged against (docs/verdict_policy.md Section 2.1,
// H3). A tester configuration parameter: this is the published default, and a
// run sets its own through `--expect ixit.param_listen_time_ms=` (IxitConfig).
inline constexpr std::chrono::seconds       kParamListenTime{10};

// Added to actual wait/listen times as slack when verifying timed behaviours.
inline constexpr std::chrono::seconds       kToleranceTime{1};

// Tolerance slack for events expressed in milliseconds.
inline constexpr std::chrono::milliseconds  kMillisecToleranceTime{100};

// Time the DUT is assumed to spend processing an incoming packet.
inline constexpr std::chrono::seconds       kProcessTime{2};

}  // namespace tc8::defaults
