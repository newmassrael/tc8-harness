#pragma once

#include <atomic>
#include <cstdint>

// SOME/IP application-layer fault flavor for the reference tc8-dut's EnhancedTestability
// service (EtsImpl). The §5.1.6 SOMEIP_ETS field get/set `_NEG` cases drive it via
// UT 0x1B OpSetEtsFlavor: a non-None flavor makes an EtsImpl field getter return a value
// that does not echo what setField stored, so the positive's post-set-readback guard goes
// from pass to fail. This is the only faithful SOME/IP fault site — the response
// serialization is vendored-vsomeip-owned, but the field value the getter returns lives in
// harness-owned EtsImpl. The flavor byte is written on the UT thread (the OpSetEtsFlavor
// handler) and read on the vsomeip dispatcher thread (the EtsImpl method), so it is an
// atomic, mirroring the lwIP fixture's g_ingress_flavor / g_egress_flavor seams.
namespace tc8::dut {

inline std::atomic<std::uint8_t> g_ets_fault_flavor{0};

inline void setEtsFaultFlavor(std::uint8_t flavor) {
    g_ets_fault_flavor.store(flavor, std::memory_order_relaxed);
}

inline std::uint8_t etsFaultFlavor() {
    return g_ets_fault_flavor.load(std::memory_order_relaxed);
}

}  // namespace tc8::dut
