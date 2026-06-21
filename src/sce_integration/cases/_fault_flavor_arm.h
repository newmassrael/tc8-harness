#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/test_config.h"
#include "stimulus/upper_tester_client.h"

// Generic lwIP-fixture fault-flavor arming, mechanism-organized and protocol-neutral
// (ARP, UDP, ... all share it). Pays the boot bring-up wait BEFORE the one-shot arm
// lands — the lwIP UT server must be listening or the raw-injected arm is lost
// (mirroring `emitStartLLAutoconfBuggy`, the §4.5 analog). lwIP-only: the
// kernel-backed reference DUT has no fixture seam and answers either flavor opcode
// with kStatusUnknownOpcode, so the matching cluster capability-skips on Linux. The
// UT-envelope identity uses TOPOLOGY values (`cfg.ipv4.tester_ip` + `cfg.dut.*`),
// never the SCXML-expectation knobs, so a `--negative` override shifts only the
// comparison, not the DUT drive.

namespace tc8::sce {

// emitEgressFlavorArm (UT 0x18 OpSetEgressFlavor): a non-None flavor makes the netif
// link-output hook corrupt one header field of the next DUT-emitted frame (ARP
// fields, UDP src/dst port / length / checksum, ...).
inline void emitEgressFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                                std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetEgressFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                         cfg.dut.mac, flavor);
}

// emitIngressFlavorArm (UT 0x19 OpSetIngressFlavor): a non-None flavor makes the
// netif input hook produce a prohibited emission (the §4.2.4.2 ARP reply / learn).
inline void emitIngressFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                                 std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetIngressFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                          cfg.dut.mac, flavor);
}

}  // namespace tc8::sce
