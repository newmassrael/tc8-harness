#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#include "tc8/upper_tester_protocol.h"

namespace tc8::dut {

// §4.7 DHCP-message field-shape mutant selector for the DHCP client. Each
// enumerator corrupts exactly one DUT-emitted DHCP-message field and is
// applied in emitDhcpMessage (switch-no-default, -Werror=switch). Its wire
// byte is **derived** from the single source of truth `tc8::ut::kDhcpFlavor*`
// (the protocol header the harness and this firmware both consume), so a
// renumber in the header flows here at compile time. Default (`None`) emits
// the fully-compliant message — what the §4.7 positive cases need, and what
// makes the negative cases' compliant branch a live conformant outcome.
// Behavioural mutants (the post-BOUND link-local leak, the pollForReply
// input-validation bypasses) live in Dhcpv4BehaviorFlavor below, not here —
// emitDhcpMessage would otherwise carry them as no-op passive breaks.
enum class Dhcpv4ClientFlavor : std::uint8_t {
    None                  = ::tc8::ut::kDhcpFlavorNone,
    // §4.7 DHCPDISCOVER field-shape mutants — each corrupts exactly one
    // DUT-emitted field so the matching §4.7 positive case's
    // field-violation branch becomes reachable. Applied in
    // emitDhcpMessage (switch-no-default). See kDhcpFlavor* for the RFC
    // clause each violates.
    DiscoverMagicCookieCorrupt = ::tc8::ut::kDhcpFlavorDiscoverMagicCookieCorrupt,
    DiscoverOmitMessageType    = ::tc8::ut::kDhcpFlavorDiscoverOmitMessageType,
    DiscoverReservedFlagsSet   = ::tc8::ut::kDhcpFlavorDiscoverReservedFlagsSet,
    DiscoverDstUnicast         = ::tc8::ut::kDhcpFlavorDiscoverDstUnicast,
    DiscoverDropEnd            = ::tc8::ut::kDhcpFlavorDiscoverDropEnd,
    DiscoverSrcNonzero         = ::tc8::ut::kDhcpFlavorDiscoverSrcNonzero,
    // §4.7 SELECTING DHCPREQUEST field-shape mutants — gated to the
    // post-OFFER REQUEST (msg_type=3) in emitDhcpMessage so the preceding
    // DISCOVER stays conformant and the OFFER lifecycle still completes.
    RequestSrcNonzero          = ::tc8::ut::kDhcpFlavorRequestSrcNonzero,
    RequestDstUnicast          = ::tc8::ut::kDhcpFlavorRequestDstUnicast,
    RequestCiaddrNonzero       = ::tc8::ut::kDhcpFlavorRequestCiaddrNonzero,
    RequestServerIdCorrupt     = ::tc8::ut::kDhcpFlavorRequestServerIdCorrupt,
    RequestRequestedIpCorrupt  = ::tc8::ut::kDhcpFlavorRequestRequestedIpCorrupt,
    // §4.7 RENEWING/REBINDING (reacquisition) REQUEST mutants — gated to
    // the reacquisition REQUEST (ciaddr != 0) in emitDhcpMessage. The
    // include mutants serve both RENEWING and REBINDING (one RFC 2131
    // §4.3.6 table 5 invariant); the dst mutant is RENEWING-specific.
    ReacqRequestIncludeServerId    = ::tc8::ut::kDhcpFlavorReacqRequestIncludeServerId,
    ReacqRequestIncludeRequestedIp = ::tc8::ut::kDhcpFlavorReacqRequestIncludeRequestedIp,
    ReacqRequestCiaddrWrong        = ::tc8::ut::kDhcpFlavorReacqRequestCiaddrWrong,
    RenewingRequestDstWrong        = ::tc8::ut::kDhcpFlavorRenewingRequestDstWrong,
    RebindingDstUnicast            = ::tc8::ut::kDhcpFlavorRebindingDstUnicast,
    // §4.7.6.9 INIT_ALLOC_09: DHCPDECLINE Option 50 mutant — a DHCP-message
    // field mutation gated to the Decline phase in emitDhcpMessage. (The
    // INIT_ALLOC_08/_10 ARP-frame mutants live in Dhcpv4ArpFlavor below so the
    // ARP emit builders switch over their own small domain, not the whole
    // DHCP-message flavor set.)
    DeclineRequestedIpWrong        = ::tc8::ut::kDhcpFlavorDeclineRequestedIpWrong,
    // §4.7 SELECTING REQUEST ↔ DISCOVER continuity mutants — each corrupts
    // one field the post-OFFER REQUEST must echo from the DISCOVER (gated to
    // the SELECTING phase in emitDhcpMessage so the DISCOVER stays conformant
    // and the OFFER lifecycle still completes). See kDhcpFlavor* for the RFC
    // clause each violates.
    RequestSecsMismatch            = ::tc8::ut::kDhcpFlavorRequestSecsMismatch,
    RequestXidMismatch             = ::tc8::ut::kDhcpFlavorRequestXidMismatch,
    RequestParamListMismatch       = ::tc8::ut::kDhcpFlavorRequestParamListMismatch,
    // §4.7 DHCPDISCOVER / SELECTING REQUEST identity-field mutants — each
    // corrupts one BOOTP identity field, gated to its phase in
    // emitDhcpMessage. See kDhcpFlavor* for the RFC clause each violates.
    DiscoverCiaddrNonzero          = ::tc8::ut::kDhcpFlavorDiscoverCiaddrNonzero,
    DiscoverChaddrMismatch         = ::tc8::ut::kDhcpFlavorDiscoverChaddrMismatch,
    RequestOmitMessageType         = ::tc8::ut::kDhcpFlavorRequestOmitMessageType,
};

// §4.7.6.9 INIT_ALLOC_08/_10 ARP-frame field mutants. Split out from
// Dhcpv4ClientFlavor (DHCP-message field mutations) so emitArpProbe /
// emitArpAnnounce do their switch-no-default over ONLY the ARP-emit domain
// instead of enumerating every DHCP-message flavor as a passive break.
enum class Dhcpv4ArpFlavor : std::uint8_t {
    None                  = ::tc8::ut::kDhcpFlavorNone,
    ProbeSenderIpNonzero  = ::tc8::ut::kDhcpFlavorProbeSenderIpNonzero,
    AnnounceSenderIpWrong = ::tc8::ut::kDhcpFlavorAnnounceSenderIpWrong,
};

// §4.5.6.1 / §4.7 BEHAVIOURAL mutants — these change the client's runtime
// behaviour (post-BOUND emit, reply acceptance) rather than the shape of a
// single emitted message, so they are dispatched in runLoop / pollForReply,
// NOT in emitDhcpMessage. Kept in their own enum (the Dhcpv4ArpFlavor split
// rationale, applied to the behavioural axis) so each behavioural dispatch
// site switches over this small domain under -Werror=switch — a new
// behavioural flavor forgotten at a dispatch site then fails to compile
// instead of silently never firing (a vacuous _neg). All three flavor enums
// share the single OpStartDhcpClient flavor byte (kDhcpFlavor* is the wire
// SSOT); the UT server routes the byte to exactly one of them by value.
enum class Dhcpv4BehaviorFlavor : std::uint8_t {
    None                  = ::tc8::ut::kDhcpFlavorNone,
    // RFC 3927 §1.9: emit one prohibited 169.254/16 ARP Probe after the
    // lease binds (runLoop). §4.5.6.1 INTRO_01_NEG drives this.
    LeakLinkLocalAfterBind = ::tc8::ut::kDhcpFlavorLeakLinkLocalAfterBind,
    // §4.7.6.9 INIT_ALLOC_04/_05: relax one pollForReply acceptance gate so
    // the client wrongly proceeds to DHCPREQUEST on a reply RFC 2131 §4.4.1
    // requires it to silently discard. Scoped to the SELECTING OFFER wait.
    AcceptMismatchedXidOffer = ::tc8::ut::kDhcpFlavorAcceptMismatchedXidOffer,
    ProceedOnLoneAck         = ::tc8::ut::kDhcpFlavorProceedOnLoneAck,
};

// TC8 §4.7 DHCPv4 client lifecycle state machine, tc8-dut side.
//
// Linux's kernel does not include a built-in DHCP client; userland
// daemons (dhcpcd, NetworkManager, systemd-networkd) own the DHCP
// state machine on real systems. The §4.7 spec body opens every
// lifecycle case with the precondition pair "DUT CONFIGURE: DHCP
// Client" → "DUT: Sends DHCPDISCOVER" → "TESTER: DHCP Server replies"
// → "DUT: Sends DHCPREQUEST", which requires a deterministic,
// observable client. This module owns:
//
//   * Phase 0: emit one DHCPDISCOVER (BOOTREQUEST, magic + Option 53
//     = 1, xid generated at start()).
//   * Phase 1: listen for a DHCPOFFER (BOOTREPLY, msg_type=2) whose
//     xid matches the DISCOVER and whose chaddr matches our MAC.
//     Capture yiaddr + server_identifier (Option 54).
//   * Phase 2: emit DHCPREQUEST (BOOTREQUEST, msg_type=3) with
//     Option 50 (requested_address = yiaddr) + Option 54
//     (server_identifier echoed) per RFC 2131 §4.3.2.
//   * Phase 3: listen for a DHCPACK (BOOTREPLY, msg_type=5) whose
//     xid + yiaddr match the REQUEST.
//   * BOUND: store yiaddr in `committed_lease_be_`. Steady-state
//     until abort() or process exit.
//
// Distinct from `LinklocalAutoconf::emitDhcpDiscover` (§4.5) which
// fires a one-shot DISCOVER with no follow-up — that path simulates
// "DHCP failed, fall back to LL". The §4.7 lifecycle path persists
// xid across DISCOVER → REQUEST and never falls back to LL.
//
// The harness chooses one of the two paths per case via the UT
// opcode (0x0C for §4.5, 0x10 for §4.7); the two state machines
// are owned independently so a future case mixing both (none today)
// can run them on separate ifaces.
class Dhcpv4Client {
public:
    // Per-instance config supplied by OpStartDhcpClient.
    //
    // Defaults are the harness fast envelope: 2 s OFFER wait, 2 s
    // ACK wait, no retry. Cases that exercise retransmission
    // (REQUEST_05, REACQUISITION_*) will override retry_count once
    // the corresponding spec procedure lands.
    struct Params {
        std::chrono::milliseconds offer_wait_ms{2000};
        std::chrono::milliseconds ack_wait_ms{2000};
        std::uint8_t              retry_count{1};
        std::chrono::milliseconds retry_interval_ms{1000};

        // §4.7.6.9 INIT_ALLOC_01 / RFC 2131 §4.4.1 SHOULD: between NAK
        // ingestion (or lease expiry) and the next DHCPDISCOVER the
        // client SHOULD wait a random interval in [1, 10] s to
        // desynchronise simultaneous restarts. `[min, max]` defines
        // the window in milliseconds; the runLoop draws `uniform_int`
        // on each restart. Both 0 (default) means "no wait" — preserves
        // S6b behaviour for cases that do not assert this timing
        // (ALLOCATING_09, REACQUISITION_08, etc.).
        std::chrono::milliseconds nak_to_discover_min_ms{0};
        std::chrono::milliseconds nak_to_discover_max_ms{0};

        // §4.7.6.9 INIT_ALLOC_08/_09/_10 / RFC 2131 §4.4.1 SHOULD:
        // post-BOUND ARP Probe + conflict-listen + Announce or DECLINE
        // sequence. Spec ParamListenTime = 10 s; the harness shrinks to
        // 1500 ms by default for INIT_ALLOC cases (Q4 — fast envelope
        // toggle) and the listener observes any tester-injected ARP
        // Reply / Request asserting the offered IP. 0 (default) means
        // "skip the probe sequence" — matches pre-S9 BOUND behaviour
        // for every other lifecycle case (SELECTING-only, RENEWING,
        // REBINDING).
        std::chrono::milliseconds arp_probe_listen_ms{0};

        // §4.7.6.3 ALLOCATING_08 / RFC 2131 §3.1 SHOULD: after a
        // DHCPDECLINE the client SHOULD wait a minimum of ten seconds
        // before restarting the configuration process to avoid
        // excessive network traffic in case of looping. Symmetric to
        // `nak_to_discover_*` but anchored on the DECLINE pivot rather
        // than the NAK / lease-expiry pivot. ALLOCATING_08 trait opts
        // in via `[10000, 11000]` ms; ALLOCATING_07 / INIT_ALLOC_09
        // keep the default `[0, 0]` (instant restart, MUST-only).
        std::chrono::milliseconds decline_to_discover_min_ms{0};
        std::chrono::milliseconds decline_to_discover_max_ms{0};

        // §4.7.6.7 CM_12/_13 / RFC 2131 §4.1: exponential-backoff
        // retransmission schedule for DISCOVERs when no OFFER replies.
        // When `retx_first_ms == 0` (default) the legacy flat
        // `retry_interval_ms` schedule is used and these knobs are
        // ignored — preserves pre-S12 behaviour for every other case.
        //
        // When `retx_first_ms > 0`:
        //   * pre-DISCOVER attempt N (zero-based) waits
        //     `min(retx_cap_ms, retx_first_ms << N)` ms,
        //     randomised by uniform_int(-retx_jitter_ms, +retx_jitter_ms).
        //   * `retry_interval_ms` is unused (the wait IS the inter-
        //     DISCOVER gap; pollForReply timeout doubles as the wait).
        //   * `retry_count` caps total DISCOVER attempts; tester emits
        //     no OFFER for CM_12/_13 so each pollForReply times out
        //     and the loop runs to attempt-exhaustion.
        //
        // CM_12 fast envelope (200 / 3200 / 100 ms): cap-doubling
        // fixpoint reached on the 6th DISCOVER (~6.2 s wall) so the
        // SCXML's 6-state lifecycle observes one cap interval.
        // CM_13 spec defaults (4000 / 64000 / 1000 ms): SCXML
        // observes 3 DISCOVERs at intervals 4±1 s and 8±1 s.
        std::chrono::milliseconds retx_first_ms{0};
        std::chrono::milliseconds retx_cap_ms{0};
        std::chrono::milliseconds retx_jitter_ms{0};

        // §4.5.6.1 / §4.7 fault-injection selector. Set only by the
        // trailing flavor byte of OpStartDhcpClient (param offset 24); the
        // compliant path leaves all three at `None` so positive cases see no
        // behavioural change. The byte selects EXACTLY ONE of: a DHCP-message
        // field mutant (`flavor`), an ARP-frame field mutant (`arp_flavor`),
        // or a behavioural mutant (`behavior_flavor`) — the UT server routes
        // by value; the other two stay None.
        Dhcpv4ClientFlavor   flavor{Dhcpv4ClientFlavor::None};
        Dhcpv4ArpFlavor      arp_flavor{Dhcpv4ArpFlavor::None};
        Dhcpv4BehaviorFlavor behavior_flavor{Dhcpv4BehaviorFlavor::None};
    };

    Dhcpv4Client();
    ~Dhcpv4Client();

    Dhcpv4Client(const Dhcpv4Client&)            = delete;
    Dhcpv4Client& operator=(const Dhcpv4Client&) = delete;

    // Bind the iface this state machine emits on. Must be called once
    // after construction, before start().
    void bind(std::string iface, std::array<std::uint8_t, 6> dut_mac);

    // Start a new state machine. If a previous one is running it is
    // aborted and joined first (matches OpStartDhcpClient idempotency).
    // Returns true on success.
    bool start(const Params& params);

    // Stop and join the state machine if running. Idempotent.
    void abort();

    // Returns the currently-bound lease (yiaddr from the matched ACK)
    // in NBO, or 0 if the state machine has not yet reached BOUND.
    // Thread-safe.
    std::uint32_t currentLeaseBe() const;

private:
    void runLoop(Params params);

    // Wire-shape control surface shared by every DHCP message emitted by
    // the client. Each emit variant (DISCOVER, SELECTING REQUEST,
    // RENEWING REQUEST, REBINDING REQUEST) builds its own spec and hands
    // it to `emitDhcpMessage`. Option 55 (Parameter Request List) is
    // always emitted — RFC 2131 §4.3.6 table 5 permits the echo in every
    // BOOTREQUEST and §4.7.6.5 PARAMETERS_04 verifies it.
    // Lifecycle phase of the message being built. Set authoritatively by
    // each emit helper (it knows which message it is emitting) and read by
    // emitDhcpMessage's fault-injection switch to gate each flavor on the
    // exact phase it targets. Carrying the phase explicitly avoids
    // re-deriving it from field values (ciaddr/dst), which would couple the
    // fault logic to the conformant field conventions — fragile precisely
    // because the flavors deliberately violate those conventions.
    enum class DhcpPhase : std::uint8_t {
        Discover,    // initial DHCPDISCOVER
        Selecting,   // SELECTING-state DHCPREQUEST (post-OFFER)
        Renewing,    // RENEWING-state DHCPREQUEST (T1, unicast to server)
        Rebinding,   // REBINDING-state DHCPREQUEST (T2, broadcast)
        Decline,     // DHCPDECLINE
    };

    struct DhcpEmitSpec {
        DhcpPhase     phase;
        std::uint8_t  msg_type;             // 1 = DISCOVER, 3 = REQUEST
        std::uint32_t xid_be;
        std::uint32_t l3_src_be;            // 0 in SELECTING phases
        std::uint32_t l3_dst_be;            // server IP (RENEWING) / broadcast
        std::uint32_t ciaddr_be;            // bound IP in RENEWING/REBINDING, 0 otherwise
        std::uint32_t requested_addr_be;    // 0 = omit Option 50
        std::uint32_t server_id_be;         // 0 = omit Option 54
    };

    // Build + inject one BOOTREQUEST datagram per `spec`. Eth-broadcast
    // (the testbed has no ARP responder for the synthetic server IP, so
    // L3 unicast on top of L2 broadcast is the conformant testbed shape;
    // see the `emitDhcpRequestRenewing` comment).
    void emitDhcpMessage(const DhcpEmitSpec& spec);

    // Build + inject one DHCPDISCOVER datagram on the bound iface.
    // Eth-broadcast, src=0.0.0.0, dst=255.255.255.255, UDP 68→67,
    // BOOTREQUEST + DHCP magic + Option 53 (DHCP Message Type) = 1.
    // `xid_be` is the persisted transaction id — used by
    // emitDhcpRequest below for spec-mandated xid continuity.
    void emitDhcpDiscover(std::uint32_t xid_be);

    // Build + inject one DHCPREQUEST per RFC 2131 §4.3.2 / §4.4.1.
    // Same envelope as DISCOVER (eth_broadcast, src=0, dst=255...,
    // UDP 68→67, BOOTREQUEST). Body adds:
    //   * Option 53 (DHCP Message Type) = 3 (DHCPREQUEST)
    //   * Option 50 (Requested IP Address) = yiaddr from OFFER
    //   * Option 54 (Server Identifier) = server_id from OFFER
    //   * 0xFF END
    void emitDhcpRequest(std::uint32_t xid_be,
                         std::uint32_t requested_addr_be,
                         std::uint32_t server_id_be);

    // RFC 2131 §4.4.5 RENEWING: client transmits DHCPREQUEST as IP
    // unicast to the server using the server's IP address. Options
    // table 5 (§4.3.6): MUST NOT include 'requested IP address' (50)
    // or 'server identifier' (54); MAY echo 'parameter request list'
    // (55). ciaddr is set to the client's bound IP. L2 stays broadcast
    // on the testbed because the emul server has no ARP responder for
    // its synthetic IP — IP-level unicast satisfies the spec; L2-level
    // addressing is an implementation detail.
    void emitDhcpRequestRenewing(std::uint32_t xid_be,
                                 std::uint32_t client_addr_be,
                                 std::uint32_t server_id_be);

    // RFC 2131 §4.4.5 REBINDING: same options constraints as RENEWING
    // but transmitted as broadcast (255.255.255.255). ciaddr = client's
    // bound IP.
    void emitDhcpRequestRebinding(std::uint32_t xid_be,
                                  std::uint32_t client_addr_be);

    // §4.7.6.9 INIT_ALLOC_09 / RFC 2131 §4.4.1, §4.4.4: emit DHCPDECLINE
    // (msg_type=4) when the post-BOUND ARP Probe detects the offered
    // address is already in use. Wire envelope mirrors DISCOVER (eth
    // broadcast, src=0, dst=255..., ciaddr=0) plus Option 50 (declined
    // address) and Option 54 (server identifier). After emitting, the
    // runLoop returns to INIT and starts a fresh DISCOVER cycle.
    void emitDhcpDecline(std::uint32_t xid_be,
                         std::uint32_t declined_addr_be,
                         std::uint32_t server_id_be);

    // §4.7.6.9 INIT_ALLOC_08 / RFC 2131 §4.4.1: ARP Request Probe shape
    // for "address-in-use" detection. sender_hw = DUT MAC, sender_ip =
    // 0, target_hw = 00..00, target_ip = `target_ip_be`. eth_dst =
    // broadcast. Distinct from §4.5 LL Probe (which targets a tentative
    // 169.254/16 IP) — the probed IP here is the OFFER's yiaddr.
    void emitArpProbe(std::uint32_t target_ip_be);

    // §4.7.6.9 INIT_ALLOC_10 / RFC 2131 §4.4.1 SHOULD: Gratuitous ARP
    // Reply broadcast announcing the just-bound IP. opcode=2,
    // sender_hw = target_hw = DUT MAC, sender_ip = target_ip =
    // `committed_ip_be`, eth_dst = broadcast.
    void emitArpAnnounce(std::uint32_t committed_ip_be);

    // §4.7.6.9 INIT_ALLOC_08/_09 post-Probe listener. Open an AF_PACKET
    // SOCK_RAW(ETH_P_ARP) socket, poll for `listen` ms, and inspect
    // every ARP frame whose sender_proto_ip equals `probed_ip_be` from
    // a non-DUT hardware address — that is the RFC 2131 §4.4.1 "address
    // appears to be in use" signal. Returns true on conflict, false on
    // timeout (no other host claims the address).
    bool runArpProbeListener(std::uint32_t              probed_ip_be,
                             std::chrono::milliseconds  listen);

    // Open + bind a UDP SOCK_DGRAM listener on INADDR_ANY:68 for the
    // DUT's iface. Returns the fd, or -1 on failure. The socket is
    // bound BEFORE the first emitDhcpDiscover so any tester reply can
    // arrive into the kernel UDP queue without racing the bind. Caller
    // owns the close.
    int openClientUdpSocket();

    // Poll the already-bound socket `sk` for a BOOTREPLY matching the
    // expected xid + chaddr. On match, populate `*out_yiaddr_be`,
    // `*out_server_id_be`, and (when non-null) `*out_lease_seconds` /
    // `*out_msg_type` from the parsed body and return true. On timeout
    // (`timeout` elapsed), return false. The lease seconds out-param
    // drives the §4.7.6.8 RENEWING/REBINDING phase machine
    // (T1=lease/2, T2=lease*7/8 per RFC 2131 §4.4.5); SELECTING-only
    // callers pass nullptr.
    //
    // `expected_msg_type` semantics:
    //   * 2 (OFFER) / 5 (ACK) / 6 (NAK) — match only this Option 53 type.
    //   * 0 — accept any BOOTREPLY; the received type is written to
    //     `*out_msg_type` (callers in the BOUND phase machine use this
    //     to distinguish ACK-renewal from NAK-back-to-INIT per
    //     RFC 2131 §4.4.5).
    //
    // §4.7.6.7 CM_05/_06 / RFC 2132 §9.3: when `out_router_be` is non-
    // null and the matched reply carries Option 3 (Router) — found in
    // the main options OR in `sname`/`file` when Option 52 (Overload)
    // expands the option scope into those BOOTP fixed fields — the
    // first 4-byte router address is written into the slot. Absence
    // leaves the slot at 0. The walker honours RFC 2132 §9.3
    // ordering (options → file → sname); on multiple Option 3
    // occurrences the LAST seen wins (matches the standard's "later
    // overrides earlier" semantics for legitimate but unusual servers
    // that split a multi-router list across regions).
    bool pollForReply(int                        sk,
                      std::chrono::milliseconds  timeout,
                      std::uint32_t              expected_xid_be,
                      std::uint8_t               expected_msg_type,
                      std::uint32_t*             out_yiaddr_be,
                      std::uint32_t*             out_server_id_be,
                      std::uint32_t*             out_lease_seconds = nullptr,
                      std::uint8_t*              out_msg_type      = nullptr,
                      std::uint32_t*             out_router_be     = nullptr);

    // RFC 2131 §4.4.5 BOUND/RENEWING/REBINDING phase machine. Driven by
    // the lease_seconds value from the matched ACK's Option 51:
    //   T1 = bound_at + lease/2     → emit RENEWING REQUEST (unicast)
    //   T2 = bound_at + lease * 7/8 → emit REBINDING REQUEST (broadcast)
    //   lease expires at bound_at + lease (return-to-INIT per §4.4.5).
    // When lease_seconds == 0 (server emul didn't advertise Option 51),
    // skip the phase machine and idle until abort — preserves pre-S6a
    // behaviour for SELECTING-only test cases.
    //
    // The phase machine continuously polls `sk` (the already-bound UDP
    // socket reused from the SELECTING phase) for BOOTREPLY datagrams
    // arriving in response to the RENEWING/REBINDING REQUESTs:
    //   * ACK (msg_type=5): re-arm BOUND/T1/T2 with the fresh lease.
    //   * NAK (msg_type=6): RFC 2131 §3.1 — return to INIT (signal via
    //     return-true so the caller restarts the DISCOVER cycle).
    //   * timeout / unknown: continue ticking until t1/t2/lease_end.
    //
    // Returns true if the caller should restart the lifecycle from
    // DHCPDISCOVER (NAK received OR lease expired without renewal).
    // Returns false if the phase machine exited because abort() was
    // called (stop_requested_).
    bool runBoundPhaseMachine(int           sk,
                              std::uint32_t xid_be,
                              std::uint32_t server_id_be,
                              std::uint32_t lease_seconds);

    // Send raw Ethernet frame on iface_ via AF_PACKET SOCK_RAW.
    int sendRaw(const std::uint8_t* frame, std::size_t len);

    // §4.7.6.7 CM_05/_06 / RFC 2131 §3.5 BOUND application of Option 3
    // (Router). Installs a default route via `gateway_be` on `iface_`
    // using ioctl(SIOCADDRT). The kernel requires the gateway to live
    // on a directly-connected subnet; the dev-netns 172.16.0.0/24
    // setup satisfies this for the harness `kDefaultServerIdBe`
    // gateway. Re-installing the same gateway is idempotent (kernel
    // returns EEXIST which we accept) so a NAK→restart→fresh-BOUND
    // cycle does not need a removal step in between.
    //
    // Returns 0 on success, negative on syscall failure. Failures are
    // not fatal — a missing default gateway just means the post-BOUND
    // egress to IP-UNUSED-ADDRESS will fail at sendto/ARP, which the
    // SCXML's deadline catches as `fail_no_dut_udp` rather than a
    // tc8-dut crash.
    int installDefaultRoute(std::uint32_t gateway_be);
    int removeDefaultRoute(std::uint32_t gateway_be);

    std::string iface_;
    std::array<std::uint8_t, 6> dut_mac_{};

    // §4.7 Phase F fault selectors. Copied from `Params` at runLoop entry.
    // `flavor_` is read by `emitDhcpMessage` (DISCOVER / SELECTING /
    // reacquisition REQUEST / DECLINE field mutants); `arp_flavor_` by
    // `emitArpProbe` / `emitArpAnnounce`; `behavior_flavor_` by `runLoop`
    // (post-BOUND link-local leak) and `pollForReply` (reply-acceptance
    // bypasses). None = conformant. Worker-thread local: written once before
    // any emit, read on the same thread, so no synchronisation is needed
    // (unlike `committed_lease_be_`, which abort() reads from the foreign
    // caller thread).
    Dhcpv4ClientFlavor   flavor_          = Dhcpv4ClientFlavor::None;
    Dhcpv4ArpFlavor      arp_flavor_      = Dhcpv4ArpFlavor::None;
    Dhcpv4BehaviorFlavor behavior_flavor_ = Dhcpv4BehaviorFlavor::None;

    mutable std::mutex lease_mu_;
    std::uint32_t      committed_lease_be_ = 0;

    // §4.7.6.7 CM_05/_06: gateway IP whose default route this client
    // currently has installed via ioctl(SIOCADDRT). 0 = no route
    // installed. Tracked so abort() can issue the matching SIOCDELRT
    // and the netns is left as we found it. Mutex-guarded with
    // `lease_mu_` because the runLoop writes it under BOUND and
    // abort() reads it from the foreign caller thread.
    std::uint32_t      installed_router_be_ = 0;

    std::atomic<bool> stop_requested_{false};
    std::thread       worker_;
};

}  // namespace tc8::dut
