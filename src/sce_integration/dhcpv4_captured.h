#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "tc8/protocol_frames/dhcpv4_frame.h"

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_ip_fragmentation.h"
#include "sce_integration/captured_l3_endpoints.h"
#include "sce_integration/captured_l4_ports.h"
#include "sce_integration/captured_trace.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed
// DHCPv4 BOOTP datagram (RFC 2131 §2). Matching SCXML declaration:
//
//   <sce:context id="captured" cpp:type="tc8::Dhcpv4Captured"
//                cpp:include="sce_integration/dhcpv4_captured.h"/>
//
// Mirror of `tc8::Dhcpv4Frame` plus a small set of member predicates
// that the §4.7 passive-observation cluster reads from SCXML guards
// (PROTOCOL_01 magic-cookie, PROTOCOL_02 message-type-option present,
// SUMMARY_04 reserved-flags-zero, CONSTRUCTING_MESSAGES_01 end-option,
// CONSTRUCTING_MESSAGES_03 source-IP-zero). Predicates live here so
// the `cpp:captured.X` → `this->captured_->X` SCE codegen rewrite
// covers every check uniformly — same pattern as
// `ArpCaptured::is_arp_probe()` and `Ipv4Captured::header_checksum_valid()`.
struct Dhcpv4Captured : CapturedFrameTiming, CapturedL3Endpoints,
                        CapturedL4Ports, CapturedIpFragmentation {
    // Encapsulating Ethernet header.
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};

    // IPv4 / UDP envelope is fully inherited: `src_ip` / `dst_ip`
    // (network byte order) from `CapturedL3Endpoints`, `src_port` /
    // `dst_port` from `CapturedL4Ports`, and `ip_flags` /
    // `ip_fragment_offset` from `CapturedIpFragmentation`.

    // BOOTP fixed body.
    std::uint8_t  op    = 0;
    std::uint8_t  htype = 0;
    std::uint8_t  hlen  = 0;
    std::uint8_t  hops  = 0;
    std::uint32_t xid   = 0;
    std::uint16_t secs  = 0;
    std::uint16_t flags = 0;
    std::uint32_t ciaddr = 0;
    std::uint32_t yiaddr = 0;
    std::uint32_t siaddr = 0;
    std::uint32_t giaddr = 0;
    std::array<std::uint8_t, 16> chaddr{};

    // Wire-derived parser flags (set by the pipeline's options walk).
    bool magic_cookie_valid           = false;
    std::uint8_t message_type         = 0;
    bool message_type_option_present  = false;
    bool last_option_is_end           = false;

    // Raw options blob covering bytes 240..end of the BOOTP body
    // (everything after the magic cookie, including the trailing 0xFF
    // END marker). Non-owning view into the libpcap-owned packet
    // memory; valid only during dispatch — copied by reference into
    // the Captured Named Context so SCXML guards firing within the
    // same `dispatchDhcpv4Frame` call have stable access. Used by
    // option-by-code lookup predicates.
    const std::uint8_t* options_data = nullptr;
    std::uint32_t       options_len  = 0;

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`.
    // REACQUISITION timing cases (_03/_04 via `ack_to_request_within_us()`)
    // and CONSTRUCTING_MESSAGES_12/_13 retransmission-backoff cases
    // dispatch via `dispatchDhcpv4Frame` (auto-managed prev snapshot on
    // fired transitions). The `last_ack/nak/decline_observed_ts_us` slots
    // below are DHCPv4-specific companions that read the inherited
    // `observed_ts_us`.

    // Most-recent ACK arrival timestamp (microseconds) seen on the
    // captured wire. Updated by `dispatchDhcpv4Frame` whenever a
    // BOOTREPLY with msg_type=5 lands, regardless of whether the
    // observation advances the SM state — so a state-3 ACK injection
    // (which doesn't satisfy `is_dhcp_request` and leaves state 3
    // intact) still records the ts. §4.7.6.8 REACQUISITION_03 (T1
    // timing) / _04 (T2 timing) read this slot via
    // `ack_to_request_within_us` to verify the interval from "sending
    // of last DHCPACK Message" (RFC 2131 §4.4.5; spec body wording at
    // tc8_p281-p300.txt:29-34, 82-87) to the DUT's RENEWING /
    // REBINDING REQUEST is within `T1 ± tol` / `T2 ± tol`.
    std::int64_t last_ack_observed_ts_us = 0;

    // §4.7.6.9 INIT_ALLOC_01 timing surface — NAK companion of
    // `last_ack_observed_ts_us`. Updated by `dispatchDhcpv4Frame`
    // whenever a BOOTREPLY with msg_type=6 lands. Read by
    // `nak_to_discover_within_us` from the post-restart DISCOVER
    // observation guard to assert the RFC 2131 §4.4.1 SHOULD random
    // wait window [1, 10+ParamToleranceTime] s between the tester's
    // DHCPNAK and the DUT's restart DHCPDISCOVER.
    std::int64_t last_nak_observed_ts_us = 0;

    // §4.7.6.3 ALLOCATING_08 timing surface — DECLINE companion of
    // `last_nak_observed_ts_us`. Updated by `dispatchDhcpv4Frame` (and
    // its cross-protocol sibling) whenever a BOOTREQUEST with
    // msg_type=4 lands. Read by `decline_to_discover_within_us` to
    // assert the RFC 2131 §3.1 SHOULD "minimum ten seconds" wait window
    // between the DUT's DHCPDECLINE and its restart DHCPDISCOVER.
    // Distinct from the NAK slot because both can be live within one
    // lifecycle (an ALLOCATING_08-style trace could hypothetically
    // overlap a NAK with a later DECLINE) — keeping them separate
    // preserves both audit trails.
    std::int64_t last_decline_observed_ts_us = 0;

    // §4.7.6.8 REACQUISITION_03 / _04 timing predicate. Returns true
    // iff a prior ACK has been observed AND the delta from that ACK
    // to the current observation lies within `[min_us, max_us]`.
    // Defensive on zero-init: if no ACK has been seen yet, returns
    // false (matches `option_be32_equals` / `option_absent` defensive
    // bias against malformed-frame false positives).
    bool ack_to_request_within_us(std::int64_t min_us,
                                   std::int64_t max_us) const noexcept {
        if (last_ack_observed_ts_us == 0) return false;
        const auto delta = observed_ts_us - last_ack_observed_ts_us;
        return delta >= min_us && delta <= max_us;
    }

    // §4.7.6.9 INIT_ALLOC_01 timing predicate. Returns true iff a prior
    // NAK has been observed AND the delta from that NAK to the current
    // observation lies within `[min_us, max_us]`. Spec body asserts
    // [1 - ToleranceTime, 10 + ToleranceTime] s; harness uses
    // [1_000_000, 11_000_000] us as the bound (ToleranceTime default
    // = 1 s). Defensive on zero-init: if no NAK has been seen yet,
    // returns false (matches `ack_to_request_within_us` convention).
    bool nak_to_discover_within_us(std::int64_t min_us,
                                    std::int64_t max_us) const noexcept {
        if (last_nak_observed_ts_us == 0) return false;
        const auto delta = observed_ts_us - last_nak_observed_ts_us;
        return delta >= min_us && delta <= max_us;
    }

    // §4.7.6.3 ALLOCATING_08 timing predicate. Returns true iff a
    // prior DECLINE has been observed AND the delta from that DECLINE
    // to the current observation lies within `[min_us, max_us]`. Spec
    // body asserts `interval > (10 - ToleranceTime) s` (RFC 2131 §3.1
    // SHOULD); harness uses `[9_000_000, 12_000_000]` us as the bound
    // (ToleranceTime default = 1 s; upper margin covers the trait's
    // [10000, 11000] ms draw without false negatives). Defensive on
    // zero-init: if no DECLINE has been seen yet, returns false.
    bool decline_to_discover_within_us(std::int64_t min_us,
                                        std::int64_t max_us) const noexcept {
        if (last_decline_observed_ts_us == 0) return false;
        const auto delta = observed_ts_us - last_decline_observed_ts_us;
        return delta >= min_us && delta <= max_us;
    }

    // §4.7.6.8 REACQUISITION_05 / _06 retransmission interval predicate.
    // Returns true iff the inter-frame delta `observed_ts_us -
    // prev_observed_ts_us` (set by `dispatchDhcpv4Frame` when the
    // previous frame advanced the SM state) lies within
    // `[min_us, max_us]`. Defensive on zero-init: if no prior
    // state-advancing observation has been recorded, returns false.
    bool frame_delta_within_us(std::int64_t min_us,
                                std::int64_t max_us) const noexcept {
        if (prev_observed_ts_us == 0) return false;
        const auto delta = observed_ts_us - prev_observed_ts_us;
        return delta >= min_us && delta <= max_us;
    }

    // Cross-message snapshot of the DUT-emitted DISCOVER fields. Populated
    // by `snapshotDiscoverFields()` from a state-entry observer fired on
    // the listening_for_discover → listening_for_request transition (see
    // `scheduleDiscoverSnapshotOnStateEntry` in
    // `dhcpv4_server_stimulus.h`). Outlives subsequent
    // `fillDhcpv4CapturedFromFrame()` calls because it lives outside the
    // wire-derived field block. §4.7.6.5 PARAMETERS_04 (Option 55 echo)
    // and §4.7.6.3 ALLOCATING_04 ('secs' echo) read these slots from
    // their pass-guards. Capacity 256 covers the full RFC 2132 §9.8
    // option value range (length byte is u8 max = 255); third-party DUTs
    // requesting more than tc8-dut's default 4-entry list never hit
    // silent truncation.
    bool          discover_snapshot_taken = false;
    std::uint16_t discover_secs           = 0;
    std::uint32_t discover_xid            = 0;
    std::array<std::uint8_t, 256> discover_param_request_list{};
    std::uint8_t                  discover_param_request_list_len     = 0;
    bool                          discover_param_request_list_present = false;

    // §4.7.6.3 ALLOCATING_04 / RFC 2131 §4.3.2: in REQUESTING state the
    // REQUEST 'secs' field MUST equal the originating DISCOVER's 'secs'.
    // False until the state-entry observer has fired (defensive — no
    // guard should reach this predicate before transition into
    // listening_for_request).
    bool secs_matches_discover() const noexcept {
        return discover_snapshot_taken && secs == discover_secs;
    }

    // §4.7.6.9 INITIALIZATION_ALLOCATION_06 / RFC 2131 §4.3.2: in
    // REQUESTING state the client MUST echo the originating DISCOVER's
    // 'xid' (which the OFFER also carries — same xid identifies the
    // exchange). Spec body wording: "Verify that received DHCPREQUEST
    // Message contains 'xid' field is set to extractedXID". The harness
    // emul OFFER faithfully echoes the captured DISCOVER xid, so this
    // predicate is equivalent to "REQUEST xid == OFFER xid". False
    // until the snapshot observer has fired.
    bool xid_matches_discover() const noexcept {
        return discover_snapshot_taken && xid == discover_xid;
    }

    // §4.7.6.5 PARAMETERS_04 / RFC 2131 §4.3.6: if the DISCOVER carries
    // Option 55, the REQUEST MUST repeat the same byte sequence. Returns
    // false (= invariant violated) when the DISCOVER had Option 55 but
    // the REQUEST is missing it / has different bytes; returns true
    // (= invariant vacuously satisfied or actually matched) when DISCOVER
    // had no Option 55 OR DISCOVER had it and REQUEST repeats it. tc8-dut
    // emits Option 55 = {1, 3, 6, 15} (subnet/router/DNS/domain) on every
    // DISCOVER (`Dhcpv4Client::emitDhcpDiscover`), so the vacuous branch
    // is unused under Topology 1; preserved for spec completeness against
    // third-party DUTs.
    bool option_param_request_list_matches_discover() const noexcept {
        if (!discover_snapshot_taken) return false;
        if (!discover_param_request_list_present) return true;  // vacuous
        if (options_data == nullptr || options_len == 0U) return false;
        std::uint32_t i = 0U;
        while (i < options_len) {
            const std::uint8_t opt = options_data[i];
            if (opt == 0xFFU) return false;
            if (opt == 0x00U) { ++i; continue; }
            if (i + 1U >= options_len) return false;
            const std::uint8_t len = options_data[i + 1U];
            if (i + 2U + len > options_len) return false;
            if (opt == 55U) {
                if (len != discover_param_request_list_len) return false;
                for (std::size_t j = 0; j < len; ++j) {
                    if (options_data[i + 2U + j] !=
                        discover_param_request_list[j]) {
                        return false;
                    }
                }
                return true;
            }
            i += 2U + len;
        }
        return false;
    }

    // State-entry observer hook. Invoked when the SM transitions into
    // listening_for_request — copies the DISCOVER field surface (just
    // populated by `fillDhcpv4CapturedFromFrame` on the DISCOVER-driven
    // dispatch) into the snapshot slots before the next REQUEST frame
    // overwrites the wire-derived block. `options_data` is a non-owning
    // pointer into pcap-managed memory which gets invalidated when the
    // dispatcher returns, so the Option 55 bytes must be COPIED into
    // the inline array — not aliased.
    void snapshotDiscoverFields() noexcept {
        discover_secs                       = secs;
        discover_xid                        = xid;
        discover_param_request_list_len     = 0;
        discover_param_request_list_present = false;
        if (options_data != nullptr && options_len != 0U) {
            std::uint32_t i = 0U;
            while (i < options_len) {
                const std::uint8_t opt = options_data[i];
                if (opt == 0xFFU) break;
                if (opt == 0x00U) { ++i; continue; }
                if (i + 1U >= options_len) break;
                const std::uint8_t len = options_data[i + 1U];
                if (i + 2U + len > options_len) break;
                if (opt == 55U) {
                    discover_param_request_list_present = true;
                    const std::size_t cap = std::min<std::size_t>(
                        len, discover_param_request_list.size());
                    discover_param_request_list_len =
                        static_cast<std::uint8_t>(cap);
                    for (std::size_t j = 0; j < cap; ++j) {
                        discover_param_request_list[j] = options_data[i + 2U + j];
                    }
                    break;
                }
                i += 2U + len;
            }
        }
        discover_snapshot_taken = true;
    }

    // §4.7.6.1 SUMMARY_04 / RFC 2131 §2: client MUST set the reserved
    // bits (1..15) of `flags` to zero. Bit 0 is the BROADCAST flag and
    // is permitted to be either polarity, so the reserved-bits check
    // masks it off rather than asserting `flags == 0` outright.
    // PROTOCOL_02-style guards layered on top of this predicate also
    // assert `op == 1` to scope the test to BOOTREQUEST.
    bool flags_reserved_bits_zero() const noexcept {
        return (flags & 0xFFFEU) == 0U;
    }

    // §4.7.6.2 PROTOCOL_02 / RFC 2131 §3: every DHCP message MUST
    // include option 53 (DHCP Message Type). True iff the pipeline's
    // options walk found a length-1 option-53 TLV in the post-magic
    // options blob. The `magic_cookie_valid` precondition is implicit
    // (the parser only sets `message_type_option_present` after the
    // cookie matches), so guards using this predicate do not need a
    // separate magic-cookie check.
    bool has_message_type_option() const noexcept {
        return message_type_option_present;
    }

    // §4.7.6.7 CONSTRUCTING_MESSAGES_01 / RFC 2131 §4.1: the last
    // option in a DHCP message MUST be the END option (0xFF). True
    // iff the pipeline's options walk terminated on a 0xFF marker
    // before running off the end of the blob. False on truncated /
    // malformed / non-DHCP frames. Implicit `magic_cookie_valid`
    // precondition (same as `has_message_type_option`).
    bool ends_with_end_option() const noexcept {
        return last_option_is_end;
    }

    // §4.7.6.7 CONSTRUCTING_MESSAGES_03 / RFC 2131 §4.1: a DHCP
    // message broadcast by a client prior to obtaining its IP
    // address has the IP source address set to 0. NBO equality
    // against the literal 0 — endianness-independent.
    bool source_ip_is_zero() const noexcept {
        return src_ip == 0U;
    }

    // §4.7.6.3 ALLOCATING_01 / RFC 2131 §3.1: the client broadcasts a
    // DHCPDISCOVER message — the IPv4 destination address MUST be the
    // limited broadcast 255.255.255.255 (NBO 0xFFFFFFFF). NBO equality
    // is endianness-independent.
    bool dst_ip_is_broadcast() const noexcept {
        return dst_ip == 0xFFFFFFFFU;
    }

    // §4.7.6.8 REACQUISITION_01 / §4.7.6.7 CONSTRUCTING_MESSAGES_02 / RFC
    // 2131 §4.4.5: the RENEWING REQUEST MUST be IP-unicast to the server
    // identified by Option 54 of the prior ACK. NBO equality against the
    // server identifier the harness emul advertised.
    bool dst_ip_equals(std::uint32_t expected_be) const noexcept {
        return dst_ip == expected_be;
    }

    // §4.7 DUT-emit filter. RFC 2131 §2 fixes htype=1 / hlen=6 for
    // Ethernet, so the first 6 bytes of the 16-byte chaddr region
    // carry the client's hardware address. True iff those 6 bytes
    // equal the supplied DUT MAC. The encapsulating eth_src is
    // *also* the DUT MAC by construction on a clean veth netns, but
    // gating on `chaddr` keeps the predicate spec-faithful (RFC 2131
    // names `chaddr` as the client identifier, not the encapsulating
    // L2 source) and robust against any future test topology where
    // a switch-mediated path could rewrite eth_src.
    bool chaddr_matches_dut_mac(
        const std::array<std::uint8_t, 6>& dut_mac) const noexcept {
        for (std::size_t i = 0; i < 6; ++i) {
            if (chaddr[i] != dut_mac[i]) return false;
        }
        return true;
    }

    // §4.7.6.5 USAGE_01 / RFC 2131 §3.6: cross-DISCOVER chaddr snapshot
    // for the multi-interface invariant. After the FIRST DUT-emitted
    // DHCPDISCOVER lands, a state-entry observer copies the captured
    // `chaddr` first-6 bytes into `discover_chaddr_snapshot`. The
    // SECOND DISCOVER's guard reads `chaddr_differs_from_snapshot()`
    // to assert the spec MUST: a DUT with multiple interfaces emits
    // each iface's DISCOVER with that iface's own hardware address —
    // a single shared chaddr would violate "DHCP through each
    // interface independently". `discover_chaddr_snapshot_taken`
    // false-defaults the predicate before the snapshot fires (no
    // false positives on out-of-order frames).
    bool                          discover_chaddr_snapshot_taken = false;
    std::array<std::uint8_t, 6>   discover_chaddr_snapshot{};

    // State-entry observer hook for the §4.7.6.5 USAGE_01 chaddr
    // snapshot (companion of `snapshotDiscoverFields()` for the
    // PARAMETERS_04 / ALLOCATING_04 cluster). Copies the first 6 bytes
    // of the just-observed DISCOVER's `chaddr` so a later DISCOVER
    // observation guard can compare against it.
    void snapshotDiscoverChaddr() noexcept {
        for (std::size_t i = 0; i < 6; ++i) {
            discover_chaddr_snapshot[i] = chaddr[i];
        }
        discover_chaddr_snapshot_taken = true;
    }

    // §4.7.6.5 USAGE_01 / RFC 2131 §3.6 predicate. Returns true iff
    // the snapshot has been taken AND the current DISCOVER's `chaddr`
    // first-6 bytes differ from the snapshot. Defensive on
    // pre-snapshot ordering: `false` before snapshot — a DISCOVER
    // observation that fires before the snapshot observer has run
    // does not satisfy the invariant (the SCXML transition guarding
    // on this predicate requires both s1 advance AND second
    // DUT-emitted DISCOVER, in that order).
    bool chaddr_differs_from_snapshot() const noexcept {
        if (!discover_chaddr_snapshot_taken) return false;
        for (std::size_t i = 0; i < 6; ++i) {
            if (chaddr[i] != discover_chaddr_snapshot[i]) {
                return true;
            }
        }
        return false;
    }

    // §4.7 BOOTP-side DUT-emit predicate. True iff the captured frame
    // is a DHCPDISCOVER carrying the magic cookie, op = BOOTREQUEST,
    // and option 53 = 1. The §4.7 passive cluster typically pairs
    // this with `chaddr_matches_dut_mac()` to scope a guard to a
    // DUT-emitted DISCOVER specifically.
    bool is_dhcp_discover() const noexcept {
        return op == 1U &&
               magic_cookie_valid &&
               message_type_option_present &&
               message_type == 1U;
    }

    // §4.7 BOOTP-side DUT-emit predicate, REQUEST sibling of
    // `is_dhcp_discover()`. True iff op = BOOTREQUEST, magic cookie
    // valid, option 53 present and = 3. Used by the §4.7.6.7 CM_04 /
    // §4.7.6.3 ALLOCATING_03/_05 / §4.7.6.8 REQUEST_01/_02 lifecycle
    // cluster to gate the second listening state's guards on a
    // DUT-emitted REQUEST (vs. the tester's injected OFFER which is
    // op = BOOTREPLY, message_type = 2).
    bool is_dhcp_request() const noexcept {
        return op == 1U &&
               magic_cookie_valid &&
               message_type_option_present &&
               message_type == 3U;
    }

    // §4.7.6.9 INIT_ALLOC_09 / RFC 2131 §4.4.4: DUT-emit DECLINE
    // predicate. Fires when the post-BOUND ARP Probe detects a
    // conflict — DUT broadcasts a BOOTREQUEST with msg_type=4
    // (DHCPDECLINE) carrying the declined yiaddr in Option 50 and the
    // server identifier in Option 54. Same op/cookie/option-53 gating
    // shape as `is_dhcp_discover` / `is_dhcp_request`.
    bool is_dhcp_decline() const noexcept {
        return op == 1U &&
               magic_cookie_valid &&
               message_type_option_present &&
               message_type == 4U;
    }

    // §4.7.6.8 REQUEST_01 / RFC 2131 §4.3.2: in REQUESTING state the
    // client MUST set 'ciaddr' = 0 (the address being requested is
    // carried in Option 50, not the BOOTP fixed header). NBO equality
    // is endianness-independent.
    bool ciaddr_is_zero() const noexcept {
        return ciaddr == 0U;
    }

    // §4.7.6.8 REQUEST_08 / REQUEST_11 / RFC 2131 §4.4.5: in
    // RENEWING / REBINDING state the client MUST set 'ciaddr' to its
    // bound IP address (the lease the renewal is extending). NBO
    // equality is endianness-independent. Used by the §4.7.6.8
    // RENEWING/REBINDING REQUEST cluster against `expected.offered_ip_be`
    // (the ACK-derived yiaddr the DUT bound to in the SELECTING phase).
    bool ciaddr_equals(std::uint32_t expected_be) const noexcept {
        return ciaddr == expected_be;
    }

    // RFC 2132 §3 / RFC 2132 §9.6 TLV walk: scan the captured options blob and
    // assert the absence of the option whose code = `code`. Returns
    // true (= invariant satisfied) iff no length-prefixed TLV with the
    // matching code is present before the END (0xFF) marker. PAD
    // (0x00) markers are skipped without advancing past END.
    //
    // Defensive on malformed frames: any structural anomaly (truncated
    // length / overrun) is treated as "option not found and parse
    // failed" → returns false (= invariant fails). This bias matches
    // `option_be32_equals`'s convention so a malformed REQUEST never
    // accidentally satisfies an absence assertion.
    //
    // Used by §4.7.6.8 REQUEST_06 / _07 / _09 / _10 (RENEWING /
    // REBINDING REQUEST MUST NOT include Option 54 / Option 50 per
    // RFC 2131 §4.3.6 table 5).
    bool option_absent(std::uint8_t code) const noexcept {
        if (options_data == nullptr || options_len == 0U) return false;
        std::uint32_t i = 0U;
        while (i < options_len) {
            const std::uint8_t opt = options_data[i];
            if (opt == 0xFFU) return true;        // END reached → absent
            if (opt == 0x00U) { ++i; continue; }  // PAD
            if (i + 1U >= options_len) return false;
            const std::uint8_t len = options_data[i + 1U];
            if (i + 2U + len > options_len) return false;
            if (opt == code) return false;        // present → invariant fails
            i += 2U + len;
        }
        return false;  // fell off the end without END → malformed
    }

    // RFC 2132 §3 / RFC 2132 §9.6 TLV walk: scan the captured options blob for
    // a length-4 option matching `code` and compare its value to the
    // 4-byte NBO `expected_be` (`*_be == NBO bytes in memory`
    // convention). Returns false on absent option, on length mismatch,
    // or when `options_data` is null (defensive — SCE codegen always
    // points it at the pipeline-provided view, but the predicate must
    // be safe against malformed frames). PAD (0x00) and END (0xFF)
    // markers are consumed without advancing past END.
    //
    // Used by §4.7.6.3 ALLOCATING_03 (Option 54 = server_id_be) and
    // §4.7.6.8 REQUEST_02 (Option 50 = offered_ip_be).
    bool option_be32_equals(std::uint8_t code,
                            std::uint32_t expected_be) const noexcept {
        if (options_data == nullptr || options_len == 0U) return false;
        std::uint32_t i = 0U;
        while (i < options_len) {
            const std::uint8_t opt = options_data[i];
            if (opt == 0xFFU) return false;       // END
            if (opt == 0x00U) { ++i; continue; }  // PAD
            if (i + 1U >= options_len) return false;
            const std::uint8_t len = options_data[i + 1U];
            if (i + 2U + len > options_len) return false;
            if (opt == code) {
                if (len != 4U) return false;
                std::uint32_t v = 0U;
                auto* vb = reinterpret_cast<std::uint8_t*>(&v);
                vb[0] = options_data[i + 2U];
                vb[1] = options_data[i + 3U];
                vb[2] = options_data[i + 4U];
                vb[3] = options_data[i + 5U];
                return v == expected_be;
            }
            i += 2U + len;
        }
        return false;
    }
};

// ADL hook called by `TestRunner<SM>` at construction. No-op for
// captured because captured fields get populated from wire frames,
// not from CLI configuration; the overload exists so the uniform
// `applyTestConfig(c, cfg)` call in TestRunner compiles for every
// Named Context type.
inline void applyTestConfig(Dhcpv4Captured & /*c*/, const TestConfig & /*cfg*/) {
}

inline void fillDhcpv4CapturedFromFrame(Dhcpv4Captured &c, const Dhcpv4Frame &f) {
    c.eth_src = f.eth_src;
    c.eth_dst = f.eth_dst;
    c.src_ip = f.src_ip;
    c.dst_ip = f.dst_ip;
    c.ip_flags = f.ip_flags;
    c.ip_fragment_offset = f.ip_fragment_offset;
    c.src_port = f.src_port;
    c.dst_port = f.dst_port;
    c.op = f.op;
    c.htype = f.htype;
    c.hlen = f.hlen;
    c.hops = f.hops;
    c.xid = f.xid;
    c.secs = f.secs;
    c.flags = f.flags;
    c.ciaddr = f.ciaddr;
    c.yiaddr = f.yiaddr;
    c.siaddr = f.siaddr;
    c.giaddr = f.giaddr;
    std::copy(f.chaddr.begin(), f.chaddr.end(), c.chaddr.begin());
    c.magic_cookie_valid = f.magic_cookie_valid;
    c.message_type = f.message_type;
    c.message_type_option_present = f.message_type_option_present;
    c.last_option_is_end = f.last_option_is_end;
    c.options_data = f.options_data;
    c.options_len  = f.options_len;
    c.observed_ts_us = f.observed_ts_us;
}

// Trace-recording hook (Evidence Export). See arp_captured.h for the
// design overview; this overload exposes the DHCPv4 cond-gating subset
// (BOOTP op + message_type + IPs + xid + key addresses). Skips the
// raw options blob since it's an unstable in-memory pointer at trace
// time; the message_type alone disambiguates DISCOVER/OFFER/REQUEST/etc.
inline void appendCapturedJson(std::string &out, const Dhcpv4Captured &c) {
    out.append("{");
    ::tc8::sce::appendUintJson(out, "\"op\":", c.op);
    ::tc8::sce::appendUintJson(out, ",\"message_type\":", c.message_type);
    ::tc8::sce::appendUintJson(out, ",\"htype\":", c.htype);
    ::tc8::sce::appendUintJson(out, ",\"hlen\":", c.hlen);
    ::tc8::sce::appendUintJson(out, ",\"xid\":", c.xid);
    ::tc8::sce::appendUintJson(out, ",\"flags\":", c.flags);
    out.append(",");
    ::tc8::sce::appendL3EndpointsJson(out, c);
    ::tc8::sce::appendL4PortsJson(out, c);
    out.append(",\"ciaddr\":");
    ::tc8::sce::appendIpv4Json(out, c.ciaddr);
    out.append(",\"yiaddr\":");
    ::tc8::sce::appendIpv4Json(out, c.yiaddr);
    out.append(",\"siaddr\":");
    ::tc8::sce::appendIpv4Json(out, c.siaddr);
    out.append(",\"eth_src\":");
    ::tc8::sce::appendMacJson(out, c.eth_src);
    out.append(",\"eth_dst\":");
    ::tc8::sce::appendMacJson(out, c.eth_dst);
    ::tc8::sce::appendTimingJson(out, c);
    out.append("}");
}

}  // namespace tc8
