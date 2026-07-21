#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <vector>

namespace tc8::stimulus {

// Locally-administered unicast MAC the tester injects as the sender-HW of
// every ARP_03..06 pre-learning frame. Distinct from the kernel-assigned
// veth-tester MAC so the cache entry the DUT learns is provably ours —
// the DUT's subsequent UDP egress must carry this MAC as Eth-dst to pass.
//
// The value is intentionally hardcoded (not read from `TestConfig::arp`)
// so `smoke-test.sh --negative` can override the *expected* MAC to prove
// the SCXML mismatch path without also changing what the stimulus injects.
// `dut/env/smoke-test.sh`'s `ARP_DUT_EXPECT_STATIC` must carry the
// same value under `--expect arp.tester_mac=...`; any drift silently turns
// the positive tests into false passes, so edit both together.
//
// RFC 7042 §2.1: the `02:` prefix marks this as a locally-administered
// unicast address, so it cannot collide with a real OUI.
inline constexpr std::array<std::uint8_t, 6> kTesterInjectedMac{
    0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};

// Second locally-administered MAC used by §4.2.4.2 Phase 3b Group C
// cases ARP_32/33/34/35, which inject two ARP frames back-to-back to
// verify RFC 826 cache-entry merging: MAC1 populates the entry, MAC2
// overwrites it, DUT's subsequent UDP egress `eth_dst` must equal MAC2.
// Same `02:` locally-administered convention as `kTesterInjectedMac`;
// distinct last-octet value keeps the two bindings unambiguous. Mirror
// the drift-safety note on `kTesterInjectedMac`: `smoke-test.sh`'s
// `ARP_TESTER_INJECTED_MAC2` must carry this literal so the SCXML
// `expected.tester_mac2` comparison is meaningful.
inline constexpr std::array<std::uint8_t, 6> kTesterInjectedMac2{
    0x02, 0x00, 0x00, 0x00, 0x00, 0xA2};

// Third locally-administered MAC used by §4.2.4.2 Phase 3c Group D
// case ARP_40 — spec sequences a tester-injected ARP Response with
// sender_hw = MAC-ADDR3 (distinct from MAC1/MAC2) so the DUT's cache
// can be unambiguously verified to learn from the *Response* path
// rather than reuse a prior MAC1/MAC2 entry. Same `02:` LAA pattern;
// `smoke-test.sh`'s `ARP_TESTER_INJECTED_MAC3` literal must agree.
inline constexpr std::array<std::uint8_t, 6> kTesterInjectedMac3{
    0x02, 0x00, 0x00, 0x00, 0x00, 0xA3};

// Which of the two §4.2.4.1 ARP Learning stimuli to emit.
//   * Request — 28-byte ARP with opcode=1, target_hw zeroed. DUT learns
//     `<sender_ip, sender_hw>` via RFC 826 §2.3 reception (ARP_03/04).
//   * GratuitousResponse — opcode=2 with target_hw=sender_hw and
//     target_ip=sender_ip, eth-dst broadcast. DUT learns via gratuitous
//     announcement, requires sysctl `arp_accept=1` on Linux (ARP_05/06).
enum class ArpLearningVariant { Request, GratuitousResponse };

// Timing envelope for the tester-side ARP Learning stimulus. Unlike the
// shared `BootTiming`, this primitive injects exactly one frame — ARP
// cache population is idempotent and the DUT's RFC 826 learning
// algorithm runs on first reception. `initial_wait` gives the DUT kernel
// a brief settle window before the injection so the subsequent UT 0x02
// stimulus (which provokes the DUT UDP egress) sees a populated cache.
struct ArpBootTiming {
    std::chrono::milliseconds initial_wait{200};
};

// Broadcast and zero MAC sentinels exposed for callers that build
// `ArpFrameSpec` literals. Defined inline here so SCXML/traits headers
// can reference them without dragging in the cpp.
inline constexpr std::array<std::uint8_t, 6> kEthBroadcast{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr std::array<std::uint8_t, 6> kEthZero{0, 0, 0, 0, 0, 0};

// Generic specification of an Ethernet-II + ARP frame for §4.2.4.2 Phase 3
// stimulus, where individual cases vary one or two of the eight fields
// (hw_type, proto_type, target_hw, target_ip, opcode, eth_dst, ...) while
// keeping the rest at RFC 826 / topology defaults. Field names mirror the
// ArpFrame dissector struct and the `--expect arp.<key>` CLI semantics.
//
// `eth_src` defaults to `sender_hw` if left zero — the wire convention
// for ARP is that the Ethernet source equals the ARP sender_hw, and
// asymmetric values are only useful for ARP_43-style negative tests.
struct ArpFrameSpec {
    std::array<std::uint8_t, 6> eth_dst = kEthBroadcast;
    std::array<std::uint8_t, 6> eth_src{};  // = sender_hw if zero
    std::uint16_t hw_type = 0x0001;         // Ethernet
    std::uint16_t proto_type = 0x0800;      // IPv4
    std::uint8_t hw_addr_len = 6;
    std::uint8_t proto_addr_len = 4;
    std::uint16_t opcode = 0x0001;          // 1 = Request, 2 = Reply
    std::array<std::uint8_t, 6> sender_hw = kTesterInjectedMac;
    std::uint32_t sender_ip_be = 0;
    std::array<std::uint8_t, 6> target_hw = kEthZero;
    std::uint32_t target_ip_be = 0;
};

// Build an Ethernet-II + ARP frame from `spec`. Frame size depends on
// `hw_addr_len` / `proto_addr_len` — for the RFC 826 Ethernet+IPv4 default
// (6/4) the frame is 42 bytes (14 B Ethernet + 28 B ARP). Callers feed the
// resulting bytes to `sendRawEthernet`.
std::vector<std::uint8_t> buildArpFrame(const ArpFrameSpec &spec);

// Convenience wrapper: 42-byte Ethernet-II + ARP Request, broadcast eth-
// dst, opcode=1, target_hw zeroed. Equivalent to `buildArpFrame` with a
// minimally-populated spec.
std::vector<std::uint8_t> buildArpRequest(const std::array<std::uint8_t, 6> &sender_hw, std::uint32_t sender_ip_be,
                                          std::uint32_t target_ip_be);

// Build a 42-byte gratuitous ARP Response frame (opcode=2, target_hw ==
// sender_hw, target_ip == sender_ip, eth-dst broadcast). Gratuitous
// Responses announce a binding without a prior Request; Linux populates
// the neigh table from these only when sysctl `arp_accept=1` is set on
// the receiving interface (see `dut/env/setup-netns.sh`).
std::vector<std::uint8_t> buildGratuitousArpResponse(const std::array<std::uint8_t, 6> &sender_hw,
                                                    std::uint32_t ip_be);

// Transmit `frame` (already including the Ethernet header) via an
// AF_PACKET SOCK_RAW socket bound to `iface`. Requires CAP_NET_RAW
// (granted to the harness binary via POST_BUILD setcap in the top-level
// CMakeLists). Returns 0 on success, a negative sentinel otherwise.
//
// The socket is opened, used once, and closed — stimulus is a one-shot
// action in the current harness, same as `sendSdMulticast` in
// `someip_sd_builder.cpp`.
int sendRawEthernet(const std::vector<std::uint8_t> &frame, std::string_view iface);

// High-level TESTER boot-time ARP Learning emit used by §4.2.4.1 cases
// ARP_03..06. Sleeps `initial_wait`, then builds and injects the frame
// matching `variant`. Caller is expected to follow with a second-stage
// stimulus (e.g. `emitTriggerSendUdpBoot`) that provokes the DUT's
// unicast UDP egress so the learned cache entry is exercised.
//
// Blocks the calling thread for `timing.initial_wait`. Returns 0 on
// success or the negative return from `sendRawEthernet`.
int emitArpLearningBoot(std::string_view iface, std::uint32_t tester_ip_be, std::uint32_t dut_ip_be,
                        ArpLearningVariant variant, const ArpBootTiming &timing = {});

// High-level TESTER boot-time emit of one fully-specified ARP frame used
// by §4.2.4.2 Phase 3 cases ARP_16..47. Sleeps `initial_wait`, then
// builds and injects `spec`. The DUT's reaction (Reply, silence, cache
// update) is observed by the SCXML guards.
//
// Unlike `emitArpLearningBoot`, no second-stage UDP-provoking stimulus
// is needed — the tester ARP Request itself is what triggers the DUT
// Reply that Phase 3 cases verify. Blocks for `timing.initial_wait`.
int emitArpFromTester(std::string_view iface, const ArpFrameSpec &spec, const ArpBootTiming &timing = {});

}  // namespace tc8::stimulus
