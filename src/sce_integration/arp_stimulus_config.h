#pragma once

#include <cstdint>

namespace tc8 {

// ARP stimulus configuration: inputs that steer how a §4.2 ARP case
// *drives* the DUT, as opposed to the values its SCXML guards compare
// observed frames against (those live in `ArpExpectations`). Carried in
// `TestConfig::arp_stimulus`, separate from the expectations DTO so the
// "expected value" abstraction stays honest — nothing here is ever
// guard-compared.
struct ArpStimulusConfig {
    // §4.2.4.2 ARP_48/49 <DYNAMIC-ARP-CACHE-TIMEOUT> in seconds, for
    // DUTs whose cache conditioning rides the UT channel (0x17
    // OpConditionArpCache). 0 = the topology conditions the DUT
    // externally (Linux netns sysctl compression) and the stimulus
    // waits for the kernel-spontaneous revalidation instead — the
    // pre-existing reference-DUT flow, unchanged by default. Non-zero =
    // the stimulus ages the DUT's table by this many virtual seconds
    // through UT 0x17 and provokes the post-timeout egress explicitly
    // (spec steps 8-11 / 12-15 rendered literally). The value must equal
    // the DUT stack's own timeout (lwIP fixture: compile-time
    // ARP_MAXAGE = 300 s) — the topology profile owns it via
    // `--expect arp_stimulus.ut_cache_conditioning_s=...`.
    std::uint16_t ut_cache_conditioning_s = 0;
};

}  // namespace tc8
