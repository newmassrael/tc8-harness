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

// The settle a per-phase `_neg` inserts AFTER arming a fault flavor mid-stream
// (emitEgressFlavorArmMidStream / emitIngressFlavorArmMidStream) and BEFORE the stimulus
// that elicits the observed segment, so the (raw-injected) arm is processed by the DUT's
// UT thread before the eliciting segment reaches the tcpip / netif-input thread. Used as
// the `initial_wait` of the eliciting emit. Egress and ingress arms share the same
// raw-inject UT path, so one settle serves both. Distinct from kTcpPilotPhaseGap (a phase
// gap), though currently the same 200 ms.
inline constexpr auto kFlavorArmSettle = std::chrono::milliseconds(200);

// The window a synthesis `_neg` holds open AFTER injecting its trigger, so the lwIP-synthesized
// RST lands and is captured before the stimulus returns and any fault resource (a stack
// TesterAutoAckDrop, the tester fd) tears down. Must stay <= the SCXML `rst_watch` deadline.
// Named to avoid aliasing kTcpUtBootWait (also 1500 ms, but the boot bring-up wait — an
// unrelated meaning that happens to share the value).
inline constexpr auto kSynthRstObserveHold = std::chrono::milliseconds(1500);

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

// emitEgressFlavorArmMidStream: arm an egress flavor MID-CONNECTION, without the
// bring-up wait (the DUT is already up and an exchange is in flight). The multi-phase
// ack `_NEG`s (TCP_HEADER_02/05/06) drive the handshake with the fault disarmed, then
// arm here between the handshake and the data injection so only the data-elicited ACK
// is corrupted — the handshake third leg (also a pure ACK) has already left. The caller
// follows with a short pre-injection wait so the arm lands before the data-ACK.
inline void emitEgressFlavorArmMidStream(const ::tc8::TestConfig &cfg, std::string_view iface,
                                         std::uint8_t flavor) {
    ::tc8::stimulus::emitSetEgressFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                         cfg.dut.mac, flavor);
}

// emitIngressFlavorArm (UT 0x19 OpSetIngressFlavor): a non-None flavor makes the
// netif input hook produce a prohibited reaction to an inbound frame — the §4.2.4.2
// ARP reply / learn emission, or the §4.6.5.4 UDP acceptance (zero the inbound UDP
// checksum so lwIP delivers a datagram it must drop).
inline void emitIngressFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                                 std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetIngressFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                          cfg.dut.mac, flavor);
}

// emitIngressFlavorArmMidStream: arm an ingress flavor MID-CONNECTION, without the bring-up
// wait (the DUT is already up and an exchange is in flight) — the ingress sibling of
// emitEgressFlavorArmMidStream. The §4.8 TCP RST-synthesis `_NEG` (ACKNOWLEDGEMENT_04)
// drives the active OPEN to ESTABLISHED with the fault disarmed, then arms here so only the
// post-handshake pure ACK triggers the synthesized RST (the handshake SYN,ACK is excluded by
// the pure-ACK gate, but arming after ESTABLISHED scopes it cleanly regardless).
inline void emitIngressFlavorArmMidStream(const ::tc8::TestConfig &cfg, std::string_view iface,
                                          std::uint8_t flavor) {
    ::tc8::stimulus::emitSetIngressFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                          cfg.dut.mac, flavor);
}

// emitAppFlavorArm (UT 0x1A OpSetAppFlavor): a non-None flavor makes the shared data
// listener skip a §4.4.4.5 destination-address discard — an application decision (RFC
// 1122) the IP stack has already delivered to the listener socket — so the DUT counts a
// datagram it must drop. A post-delivery seam, not a frame mutation.
inline void emitAppFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                             std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetAppFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                      cfg.dut.mac, flavor);
}

// emitEtsFlavorArm (UT 0x1B OpSetEtsFlavor): a non-None flavor makes the reference tc8-dut's
// SOME/IP EtsImpl field getter return a corrupted value, so a buggy DUT surfaces a post-set
// readback that does not echo what was set (§5.1.6 SOMEIP_ETS field get/set guards). The only
// faithful SOME/IP fault site (the wire serialization is vendored vsomeip; the field value is
// EtsImpl-owned). tc8-dut-only.
inline void emitEtsFlavorArm(const ::tc8::TestConfig &cfg, std::string_view iface,
                             std::uint8_t flavor) {
    if (cfg.stimulus_timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(cfg.stimulus_timing.initial_wait);
    }
    ::tc8::stimulus::emitSetEtsFlavor(iface, cfg.ipv4.tester_ip, cfg.dut.ip,
                                      cfg.dut.mac, flavor);
}

}  // namespace tc8::sce
