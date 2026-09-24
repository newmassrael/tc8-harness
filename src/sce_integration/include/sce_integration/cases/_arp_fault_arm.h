#pragma once

// The ARP-shaped composition of the generic fault arming — split out of
// `_arp_traits_base.h` on 2026-09-25 so that base, which EVERY §4.2 case includes,
// stops carrying the fault-flavour catalogue.
//
// ⚠ Why the split exists, measured rather than argued: the catalogue reaches consumers
// through `_fault_flavor_arm.h`, and the ARP base included that for this one function.
// Since all 64 ARP cases include the base and the registrar buckets them by an MD5 of
// the case id, the catalogue landed in every chunk — so touching one flavour constant
// still recompiled 23 of 25 registrar TUs even after the catalogue had its own header
// (docs/tech-debt.md TD-44). Six case headers use this function; the other 800 were
// paying for it.
//
// Include this from an ARP `_neg` case that needs the composition. A case that only
// arms (the common shape) includes `_fault_flavor_arm.h` directly and needs nothing
// here.

#include <chrono>
#include <cstdint>
#include <string_view>

#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_config.h"
#include "stimulus/boot_timing.h"

namespace tc8::sce {

// Request-shape egress `_neg` stimulus (ARP_07..12): arm the egress fault, then drive
// the same UT 0x02 egress provocation the positive case uses so the lwIP DUT emits a
// cache-miss ARP Request the hook corrupts. The provocation's own bring-up wait is
// suppressed — `emitEgressFlavorArm` already paid it, and the UT server is now proven
// up — so the two emits do not double the pause. The deadline does not arm until
// kickStimulus returns (test_runner.h), so this whole block runs before the listen
// window opens and the corrupted Request is captured either way.
inline void emitEgressFlavorRequestProvocation(const ::tc8::TestConfig &cfg,
                                               std::string_view iface,
                                               ::tc8::sce::IDutControl &dut,
                                               std::uint8_t flavor) {
    emitEgressFlavorArm(cfg, iface, flavor);
    ::tc8::stimulus::BootTiming timing = cfg.stimulus_timing;
    timing.initial_wait = std::chrono::milliseconds{0};
    emitArpEgressProvocation(dut, timing);
}

}  // namespace tc8::sce
