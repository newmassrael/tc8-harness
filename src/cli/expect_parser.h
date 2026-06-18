#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sce_integration/arp_expectations.h"
#include "sce_integration/arp_stimulus_config.h"
#include "sce_integration/dhcpv4_expectations.h"
#include "sce_integration/dut_identity.h"
#include "sce_integration/icmpv4_expectations.h"
#include "sce_integration/ipv4_expectations.h"
#include "sce_integration/someip_expectations.h"

namespace tc8::cli {

// Parses a numeric literal (decimal or 0x-prefixed hex) into a 64-bit
// value. Returns false if `text` is empty, contains garbage, or does not
// fit in uint64_t. Caller range-checks against the target field size.
// Exposed for unit tests; production callers use `applyExpectToken` which
// wraps this plus per-key range checks.
bool parseNumeric(std::string_view text, std::uint64_t &out);

// Parses an IPv4 dotted-decimal literal (e.g. "172.16.0.1") into a 32-bit
// value held in network byte order — the same encoding as
// `inet_pton(AF_INET, ...)` and as `static_cast<uint32_t>(Tins::IPv4Address)`.
// Comparing the result against captured `*_proto_ip` fields therefore needs
// no swap. Returns false on empty input, non-IPv4 syntax, or out-of-range
// octets.
bool parseIpv4Dotted(std::string_view text, std::uint32_t &out);

// Parses a MAC literal in colon-separated hex form (e.g. "aa:bb:cc:dd:ee:ff",
// case-insensitive). Returns false unless the input is exactly six octets
// separated by ':' with each octet a 1- or 2-digit hex value. The 6-byte
// array is filled in over-the-wire order, matching the layout of
// `Tins::HWAddress<6>` and `tc8::ArpFrame::*_hw`.
bool parseMac(std::string_view text, std::array<std::uint8_t, 6> &out);

// Applies a single `--expect key=value` token to `e`. Recognised keys:
// service_id (uint16), instance_id (uint16), major_version (uint8),
// ttl (uint24 — SD TTL is 24-bit big-endian), minor_version (uint32),
// eventgroup_id (uint16 — Type 2 entry eventgroup identifier),
// dut_iface_ip / sd_multicast_ip / mcast_ipv4 (IPv4 dotted, NBO),
// udp_port / tcp_port / mcast_port (uint16),
// payload (colon-separated hex byte list, e.g. 00:00:34:68 — the expected
//   L7 Method-Response echo; ETS conds assert it, --negative flips a byte).
// Returns false when:
//   - the token has no '=' separator,
//   - the value doesn't parse as a numeric literal,
//   - the value overflows the target field,
//   - the key is not in the recognised set.
// On false, `e` is left untouched for whichever field the token targeted.
bool applyExpectToken(std::string_view token, ::tc8::SomeIpExpectations &e);

// Applies a single `--expect arp.<key>=<value>` token to `e`. Recognised
// keys (with the `arp.` prefix stripped):
//   dut_iface_ip  — IPv4 dotted, network byte order. *SCXML expectation*
//                   the captured DUT frames are compared against.
//   tester_ip     — IPv4 dotted, network byte order
//   dut_iface_mac — six colon-separated hex octets. *SCXML expectation*.
//   tester_mac    — six colon-separated hex octets. The *expectation* of
//                   the MAC the tester injects as sender-HW in §4.2.4.1
//                   ARP Learning stimulus; the stimulus itself uses
//                   `tc8::stimulus::kTesterInjectedMac` (hardcoded), so
//                   this knob is purely a comparison target for SCXML
//                   guards and `--negative` mismatch rows.
//   tester_mac2   — six colon-separated hex octets. *Expectation* of the
//                   second tester MAC used by §4.2.4.2 Phase 3b Group C
//                   cache-merge cases (ARP_32/33/34/35). Same hardcoded-
//                   in-stimulus (kTesterInjectedMac2) / expected-via-CLI
//                   split as `tester_mac`.
// Returns false when the token lacks the `arp.` prefix, the value fails
// its per-key parser, or the post-prefix key is unknown. Tokens without
// the prefix are not the ARP overload's responsibility — `test_command`
// chains the protocol-scoped overloads and surfaces a single
// "unrecognised token" error if every overload returns false.
bool applyExpectToken(std::string_view token, ::tc8::ArpExpectations &e);

// Applies a single `--expect dut.<key>=<value>` token to `e` — the
// DUT's wire identity, the address frames are sent *to* (never guard-
// compared; see `DutIdentity`). Recognised keys (prefix stripped):
//   ip   — IPv4 dotted, network byte order. The L3 destination every
//          protocol's stimulus targets (was `arp.dut_real_ip`).
//   mac  — six colon-separated hex octets, over-the-wire order. The
//          Ethernet destination every emitter uses (was
//          `arp.dut_real_mac`).
// Returns false when the token lacks the `dut.` prefix, the value fails
// its per-key parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::DutIdentity &e);

// Applies a single `--expect arp_stimulus.<key>=<value>` token to `e` —
// ARP stimulus knobs that steer a case rather than gate its verdict
// (never guard-compared; see `ArpStimulusConfig`). Recognised keys:
//   ut_cache_conditioning_s — uint16 seconds. §4.2.4.2 ARP_48/49
//          <DYNAMIC-ARP-CACHE-TIMEOUT> for UT-channel cache conditioning
//          (was `arp.ut_cache_conditioning_s`).
// Returns false when the token lacks the `arp_stimulus.` prefix, the
// value fails its parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::ArpStimulusConfig &e);

// Applies a single `--expect icmpv4.<key>=<value>` token to `e`.
// Recognised keys (with the `icmpv4.` prefix stripped):
//   tester_ip     — IPv4 dotted, network byte order. Source address of
//                   the tester-sent Echo Request and expectation against
//                   the captured DUT Echo Reply's destination.
//   dut_iface_ip  — IPv4 dotted, network byte order. Target of the
//                   tester-sent Echo Request and expectation against
//                   the captured DUT Echo Reply's source.
//   echo_id       — uint16. §4.3.3.2 TYPE_09 identifier expectation the
//                   SCXML guard compares `captured.echo_id` against.
//                   Tester stimulus hardcodes the matching literal in
//                   `stimulus/icmpv4_builder.h::kIcmpEchoId`; CLI flips
//                   this knob to prove SCXML mismatch paths via
//                   `--negative` without also shifting what the tester
//                   sends.
//   echo_seq      — uint16. Sequence-number sibling of `echo_id`; the
//                   matching constant is `kIcmpEchoSeq` in the builder.
// Returns false when the token lacks the `icmpv4.` prefix, the value
// fails its per-key parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::Icmpv4Expectations &e);

// Applies a single `--expect ipv4.<key>=<value>` token to `e`. Recognised
// keys (with the `ipv4.` prefix stripped):
//   tester_ip     — IPv4 dotted, network byte order. Tester's source
//                   address; unused in the §4.4 pilot SCXML guards but
//                   carried for symmetry with `Icmpv4Expected` and for
//                   future §4.4.4.2 symmetric checks.
//   dut_iface_ip  — IPv4 dotted, network byte order. The `dispatch()`
//                   filter in every §4.4 case drops packets whose
//                   `src_ip != expected.dut_iface_ip` so only DUT-
//                   originated frames drive the state machine;
//                   HEADER_03's SCXML pass guard additionally compares
//                   `captured.src_addr == expected.dut_iface_ip`.
// Returns false when the token lacks the `ipv4.` prefix, the value
// fails `parseIpv4Dotted`, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::Ipv4Expectations &e);

// Applies a single `--expect dhcpv4.<key>=<value>` token to `e`.
// Recognised keys (with the `dhcpv4.` prefix stripped):
//   dut_iface_mac — six colon-separated hex octets. *SCXML expectation*:
//                   the DUT's iface MAC as it appears in `chaddr` of a
//                   DUT-emitted DISCOVER. §4.7 passive-observation
//                   cases gate their pass/fail predicates on
//                   `captured.chaddr_matches_dut_mac(expected.dut_iface_mac)`
//                   so non-DUT DHCP traffic (none on a clean veth
//                   netns, but ambient on a shared lab segment) does
//                   not drive verdicts.
// Returns false when the token lacks the `dhcpv4.` prefix, the value
// fails its per-key parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::Dhcpv4Expectations &e);

// Apply a batch of raw `--expect-extra` tokens to an out-of-tree OEM
// Context, calling `applyExpectToken(token, e)` per token via ADL. An
// OEM provides one overload `applyExpectToken(std::string_view, OemCtx&)`
// in its own namespace and wires this into its
// `applyTestConfig(OemCtx&, cfg)` seam:
//
//   void applyTestConfig(OemCtx& ctx, const tc8::TestConfig& cfg) {
//       tc8::cli::applyExpectTokens(cfg.expect_extra_tokens, ctx);
//   }
//
// so a deployment-varying OEM value reaches the case's Expected without
// editing core `expect_parser`. In-tree Contexts never use this — their
// values arrive through the strict `--expect` parser and the closed
// TestConfig sub-structs. Unrecognised tokens are silently skipped (the
// OEM overload returns false), so the OEM owns validation of its own key
// namespace.
template <typename Context>
void applyExpectTokens(const std::vector<std::string> &tokens, Context &e) {
    for (const auto &tok : tokens) {
        applyExpectToken(tok, e);
    }
}

}  // namespace tc8::cli
