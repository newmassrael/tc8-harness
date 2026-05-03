#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "sce_integration/arp_expectations.h"
#include "sce_integration/dhcpv4_expectations.h"
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
// eventgroup_id (uint16 — Type 2 entry eventgroup identifier).
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
//   dut_real_ip   — IPv4 dotted, network byte order. *Stimulus input*:
//                   the target_ip of the tester-injected ARP Request.
//                   Kept separate from `dut_iface_ip` so `--negative` can
//                   override the SCXML expectation (ARP_44) without
//                   silencing the DUT.
//   dut_real_mac  — six colon-separated hex octets. *Stimulus input*:
//                   the target_hw the tester uses when addressing a frame
//                   directly to the DUT (ARP_19/42). Separate from
//                   `dut_iface_mac` for the same reason as `dut_real_ip`.
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

}  // namespace tc8::cli
