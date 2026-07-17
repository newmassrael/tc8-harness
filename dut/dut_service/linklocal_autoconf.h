#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "tc8/rfc3927_constants.h"
#include "tc8/upper_tester_protocol.h"

#include "net/raw_packet_socket.h"

namespace tc8::dut {

// TC8 §4.5 IPv4 Link-Local Autoconfiguration (RFC 3927) tc8-dut
// state machine.
//
// Linux's kernel does not implement RFC 3927 — userland tools
// (avahi-autoipd, dhcpcd --noarp --waitip=4, NetworkManager) handle
// LL probing. The harness needs to drive this from the tc8-dut so
// the §4.5 case bodies (which open with "DUT CONFIGURE: bring up
// iface" → "DUT: Sends DHCPDISCOVER" → DUT begins LL probing) have
// a deterministic, observable trigger. This module owns:
//
//   * One DHCPDISCOVER egress, on receipt of OpStartLLAutoconf, so
//     the Pass Criteria step "DUT: Sends DHCPDISCOVER Message" is
//     satisfied — the tc8-dut is the DHCP "client" emitting one
//     observable Discover before falling back to LL.
//   * RFC 3927 PROBE phase: pick a random 169.254.X.Y address
//     (X in [1, 254] per RFC 3927 §2.1 reserved-range rule), wait
//     PROBE_WAIT, emit 3 ARP Probes spaced PROBE_MIN..PROBE_MAX.
//   * RFC 3927 ANNOUNCE phase: wait ANNOUNCE_WAIT after the third
//     Probe, emit 2 ARP Announces spaced ANNOUNCE_INTERVAL.
//   * Steady-state: the state machine commits the address; future
//     §4.5 cases (CONFLICT_*) extend this to defend / cease.
//
// All timings are caller-supplied via OpStartLLAutoconf so per-case
// SCXML deadlines stay compact. Wire-format builders are inlined
// in linklocal_autoconf.cpp to keep tc8-dut self-contained from
// src/stimulus/ (the harness binary's stimulus library).
// Fault-injection flavor selector, mapped 1:1 onto §4.5.6.2 cluster A
// (Probe-shape) and §4.5.6.3 ANNOUNCING (Announce-shape) invariants.
// Each enumerator's wire byte is **derived** from the single source of
// truth `tc8::ut::kFlavor*` (the protocol header the harness and this
// firmware both consume), so the two can never silently diverge — a
// renumber in the header flows here at compile time. Default (`None`)
// emits a fully-compliant Probe + Announce — a buggy caller that
// forgets to set `Params::flavor` falls through to the conformant
// path rather than silently injecting a fault, which is what the
// negative-case self-validation needs.
//
// Each emit builder (`emitArpProbe`, `emitArpAnnounce`,
// `emitArpReply`) does a switch-no-default over this enum. A flavor
// active in one builder is a passive `break` in the other two, so
// `-Wswitch` makes the compiler force every new flavor to be
// considered in ALL THREE — preventing a future Probe/Announce/Reply
// flavor that silently leaks a mutation into the wrong frame shape.
enum class LinklocalAutoconfFlavor : std::uint8_t {
    None                          = ::tc8::ut::kFlavorNone,
    // §4.5.6.2 Probe-shape mutations.
    SenderIpNonzero               = ::tc8::ut::kFlavorSenderIpNonzero,
    TargetOutsidePrefix           = ::tc8::ut::kFlavorTargetOutsidePrefix,
    TargetInReservedRange         = ::tc8::ut::kFlavorTargetInReservedRange,
    TargetHwNonzero               = ::tc8::ut::kFlavorTargetHwNonzero,
    SenderHwWrong                 = ::tc8::ut::kFlavorSenderHwWrong,
    // §4.5.6.3 Announce-shape mutations.
    AnnounceEthDstUnicast         = ::tc8::ut::kFlavorAnnounceEthDstUnicast,
    AnnounceSenderTargetMismatch  = ::tc8::ut::kFlavorAnnounceSenderTargetMismatch,
    AnnounceSenderHwWrong         = ::tc8::ut::kFlavorAnnounceSenderHwWrong,
    AnnounceTargetHwNonzero       = ::tc8::ut::kFlavorAnnounceTargetHwNonzero,
    // §4.5.6.2 Probe-shape mutation (header appends its wire byte after
    // the Announce block to keep existing values stable).
    ProbeEthDstUnicast            = ::tc8::ut::kFlavorProbeEthDstUnicast,
    // §4.5.6.2 _16 / §4.5.6.4 CONFLICT_11 defending-Reply-shape
    // mutations (RFC 3927 §2.5). emitArpReply does its own
    // switch-no-default; Probe/Announce builders break passively.
    ReplySenderIpWrong            = ::tc8::ut::kFlavorReplySenderIpWrong,
    ReplyEthDstUnicast            = ::tc8::ut::kFlavorReplyEthDstUnicast,
    // Responder-dispatch mutation (RFC 3927 §2.7): makes the responder
    // answer ARP Requests for unclaimed targets. Read by
    // runArpResponder's target gate, NOT an emit-field mutation, so it
    // is a passive `break` in all three emit-builder switches.
    ReplyToArbitraryTarget        = ::tc8::ut::kFlavorReplyToArbitraryTarget,
    // Steady-state cadence mutation (RFC 3927 §4 SHOULD NOT): makes the
    // committed host re-emit the Announce-shaped gratuitous ARP on a
    // cadence. Read by runLoop's steady-state defend loop, NOT an
    // emit-field mutation, so it is a passive `break` in all three
    // emit-builder switches. §4.5.6.6 NETWORK_PARTITIONS_01_NEG2.
    EmitPeriodicGratuitous        = ::tc8::ut::kFlavorEmitPeriodicGratuitous,
    // §4.5.6.2 _14/_15 conflict-resolution rate-limit mutations
    // (RFC 3927 §2.2.1). Each violates one rate-limit invariant at a
    // specific point in the conflict sequence (the run is conformant up
    // to that guard). Read by runLoop's conflict loop, NOT emit-field
    // mutations, so all four are passive `break`s in the emit builders.
    ReprobeStaleCycle             = ::tc8::ut::kFlavorReprobeStaleCycle,
    SkipFirstRateLimitSilence     = ::tc8::ut::kFlavorSkipFirstRateLimitSilence,
    ReprobeStalePostSilence       = ::tc8::ut::kFlavorReprobeStalePostSilence,
    SkipSecondRateLimitSilence    = ::tc8::ut::kFlavorSkipSecondRateLimitSilence,
};

class LinklocalAutoconf {
public:
    // Per-instance config supplied by OpStartLLAutoconf{,Buggy}.
    // Defaults listed here are the harness "fast" envelope (sum ~ 1.5 s
    // wall), not the RFC defaults — callers that need spec timings
    // (the §4.5.6.2 _09/_10 cadence cases) override explicitly.
    //
    // `flavor` is set only by the OpStartLLAutoconfBuggy path; the
    // compliant 0x0C opcode leaves it at `None` so the existing
    // §4.5.6.2 positive cases see no behavioural change.
    struct Params {
        std::chrono::milliseconds dhcp_timeout_ms{200};
        std::chrono::milliseconds probe_wait_ms{200};
        std::chrono::milliseconds probe_min_ms{200};
        std::chrono::milliseconds probe_max_ms{300};
        std::chrono::milliseconds announce_wait_ms{200};
        std::chrono::milliseconds announce_interval_ms{200};
        // RFC 3927 §2.2.1 RATE_LIMIT_INTERVAL. Once
        // tc8::rfc3927::kMaxConflicts is reached the host enters
        // rate-limit mode: each subsequent probe attempt is preceded
        // by a sleep of this duration, so the host emits at most one
        // new address per interval. Default mirrors the RFC's 60 s;
        // harness fast envelope overrides to 3 s for §4.5.6.2 _14
        // SCXML deadline fit.
        std::chrono::milliseconds rate_limit_interval_ms{
            tc8::rfc3927::kRateLimitIntervalMs};
        LinklocalAutoconfFlavor   flavor{LinklocalAutoconfFlavor::None};
    };

    LinklocalAutoconf();
    ~LinklocalAutoconf();

    LinklocalAutoconf(const LinklocalAutoconf&)            = delete;
    LinklocalAutoconf& operator=(const LinklocalAutoconf&) = delete;

    // Bind the iface this state machine emits on. Must be called
    // once after construction, before start().
    void bind(std::string iface,
              std::array<std::uint8_t, 6> dut_mac,
              std::uint32_t dut_iface_ip_be);

    // Start a new state machine. If a previous one is running it is
    // aborted and joined first (matches OpStartLLAutoconf
    // idempotency). Returns true on success.
    bool start(const Params& params);

    // Stop and join the state machine if running. Idempotent.
    void abort();

    // Returns the currently-committed LL address in NBO, or 0 if not
    // yet committed. Thread-safe.
    std::uint32_t currentAddressBe() const;

private:
    void runLoop(Params params);

    // Build + inject a DHCPDISCOVER datagram. Eth-broadcast,
    // src=0.0.0.0, dst=255.255.255.255, UDP 68→67, BOOTREQUEST + DHCP
    // magic + Option 53 (DHCP Message Type) = 1.
    void emitDhcpDiscover();

    // Build + inject an ARP Probe (sender_ip=0, sender_hw=DUT MAC,
    // target_hw=00:00:00:00:00:00, target_ip=tentative LL,
    // Eth-broadcast). Per RFC 3927 §2.1.1. `flavor` mutates exactly
    // one field per fault-injection variant (see LinklocalAutoconf-
    // Flavor doc above); `None` emits the spec-compliant shape.
    void emitArpProbe(std::uint32_t tentative_ll_be,
                      LinklocalAutoconfFlavor flavor);

    // Build + inject an ARP Announce (sender_ip=target_ip=committed
    // LL, sender_hw=DUT MAC, target_hw=00:00:00:00:00:00,
    // Eth-broadcast). Per RFC 3927 §2.4. `flavor` mutates exactly
    // one Announce field per fault-injection variant (see
    // LinklocalAutoconfFlavor doc above); `None` and Probe-phase
    // flavors emit the spec-compliant shape.
    void emitArpAnnounce(std::uint32_t committed_ll_be,
                         LinklocalAutoconfFlavor flavor);

    // Pick a random LL address in 169.254.1.0..169.254.254.255 (avoid
    // reserved first/last 256 per RFC 3927 §2.1). Seeded from time
    // + DUT MAC so successive case runs see different picks.
    std::uint32_t pickLLAddress();

    // Send raw Ethernet frame on iface_ via the shared reusing emitter.
    int sendRaw(const std::uint8_t* frame, std::size_t len);

    // RFC 3927 §2.2.1 conflict listener. Spawns a thread bound to
    // AF_PACKET ETH_P_ARP that watches for conflict shapes against
    // `tentative_ll_be` until stopped. Sets `conflict_detected_` and
    // exits on the first hit. Cleared between probe attempts so a
    // re-picked address starts with a clean slate. §4.5.6.2 _11/_12/_13
    // exercise this path.
    void runConflictListener(std::uint32_t tentative_ll_be);
    void startConflictListener(std::uint32_t tentative_ll_be);
    void stopConflictListener();

    // RFC 3927 §2.5 post-claim ARP responder + defender-cease watcher.
    // Spawned after Phase 2 commit: a thread bound to AF_PACKET
    // ETH_P_ARP watches every ARP frame on the iface and dispatches
    // by predicate. Self-emit reflection (AF_PACKET delivers our own
    // TX to all listeners on the iface) is filtered by `sender_hw ==
    // dut_mac_` — identical pattern to the probing-window conflict
    // listener.
    //
    //   * Conflict (sender_proto_ip == committed_LL, opcode in {1,2}):
    //     RFC 3927 §2.5 conflicting-ARP detection. Set
    //     `cease_requested_` and let the worker thread tear down the
    //     claim, clear the address, and re-enter Phase 1 (always-cease
    //     branch — RFC 3927 §2.5 method 1 "configure a new address").
    //     §4.5.6.4 CONFLICT_06..10 verify this branch.
    //   * Reply-target (opcode == 1, target_proto_ip == committed_LL):
    //     emit broadcast ARP Reply per RFC 3927 §2.5 last MUST.
    //     §4.5.6.2 _16 and §4.5.6.4 CONFLICT_11 verify this branch.
    //
    // The two predicates are ordered: conflict supersedes Reply, so
    // a Request with sender == target == committed_LL (the §4.5.6.4
    // claim-hijacking shape) drives cease without first emitting a
    // doomed Reply.
    void runArpResponder();
    void startArpResponder();
    void stopArpResponder();
    // `flavor` mutates exactly one Reply field per fault-injection
    // variant (RFC 3927 §2.5); `None` and Probe/Announce-phase flavors
    // emit the spec-compliant broadcast Reply. Sourced from `flavor_`
    // by the responder thread (set once in runLoop before spawn).
    void emitArpReply(std::uint32_t target_ip_be,
                      const std::array<std::uint8_t, 6>& target_hw,
                      LinklocalAutoconfFlavor flavor);

    // The reusing raw emitter. NOT a socket per message — see
    // `tc8::net::RawPacketSocket`. Here the bias mattered even more than in
    // Dhcpv4Client: ANNOUNCING_06 asserts a 2 s ANNOUNCE_INTERVAL within
    // [1950, 2050] ms, so ~32 ms spent 64% of the tolerance and left ~18 ms
    // of headroom — a latent failure. Driven only by `worker_`.
    ::tc8::net::RawPacketSocket raw_tx_;

    std::string iface_;
    std::array<std::uint8_t, 6> dut_mac_{};
    std::uint32_t dut_iface_ip_be_ = 0;

    // Fault-injection flavor for the responder thread's defending
    // Reply. Set once at the top of runLoop (before the responder is
    // spawned, which is the happens-before barrier) and read-only
    // thereafter, so a plain member is race-free.
    LinklocalAutoconfFlavor flavor_ = LinklocalAutoconfFlavor::None;

    mutable std::mutex address_mu_;
    std::uint32_t committed_address_be_ = 0;

    std::atomic<bool> stop_requested_{false};
    std::thread       worker_;

    std::atomic<bool> conflict_detected_{false};
    std::atomic<bool> stop_listener_{false};
    std::thread       listener_thread_;

    std::atomic<bool> stop_responder_{false};
    std::thread       responder_thread_;
    // Set by runArpResponder after AF_PACKET socket+bind succeeds.
    // startArpResponder blocks on this so callers (Phase 2's first
    // Announce + the §4.5.6.2 _16 / §4.5.6.4 _11 claim-condition
    // observer) see the responder as fully ready — closing the race
    // where a tester Request landed before the responder was bound
    // and was silently dropped (manifested as 60%+ flake at
    // 4-parallel workers in Session 8).
    std::atomic<bool> responder_ready_{false};

    // RFC 3927 §2.5 always-cease signal. Responder thread sets this
    // when a conflicting ARP frame lands (sender_proto_ip ==
    // committed_LL, sender_hw != dut_mac_); `runLoop`'s outer loop
    // observes it, tears down the claim, and re-enters Phase 1 with
    // a freshly-picked LL. Cleared by the worker after re-entering
    // Phase 1 so a subsequent steady-state conflict can re-arm it.
    // §4.5.6.4 CONFLICT_06..10 verify this branch.
    std::atomic<bool> cease_requested_{false};
};

}  // namespace tc8::dut
