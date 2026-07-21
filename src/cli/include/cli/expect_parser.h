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

// Applies a single `--expect key=value` token (no namespace prefix) to `e`.
// The accepted keys, their value kinds (uint8/16/24/32, IPv4-dotted-NBO, MAC,
// hex-payload) and ranges are the SSOT in src/cli/tc8_expect_keys.def, from
// which this parser is generated — so this comment does not re-list them.
// Semantic note: `payload` is the expected L7 Method-Response echo (ETS conds
// assert it; `--negative` flips a byte). Returns false when the token has no
// '=', the value fails its kind's parser or overflows the field, or the key is
// not in the schema; on false `e` is left untouched.
bool applyExpectToken(std::string_view token, ::tc8::SomeIpExpectations &e);

// Applies a single `--expect arp.<key>=<value>` token to `e`. The `arp.`
// prefix and the key set are the SSOT in tc8_expect_keys.def. Semantic note:
// the `tester_mac`/`tester_mac2`/`tester_mac3` keys are *expectations*
// (comparison targets for SCXML guards and `--negative` mismatch rows in the
// §4.2.4.1 / §4.2.4.2 ARP cases); the MAC the tester actually injects is
// hardcoded in stimulus (`tc8::stimulus::kTesterInjectedMac*`). Returns false
// when the token lacks the `arp.` prefix, the value fails its parser, or the
// post-prefix key is unknown. Tokens without the prefix are not this overload's
// responsibility — `test_command` chains the protocol-scoped overloads and
// surfaces a single "unrecognised token" error if every overload declines.
bool applyExpectToken(std::string_view token, ::tc8::ArpExpectations &e);

// Applies a single `--expect dut.<key>=<value>` token to `e` — the DUT's wire
// identity, the address frames are sent *to* (never guard-compared; see
// `DutIdentity`). The `dut.` prefix and key set are the SSOT in
// tc8_expect_keys.def. Returns false when the token lacks the `dut.` prefix,
// the value fails its parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::DutIdentity &e);

// Applies a single `--expect arp_stimulus.<key>=<value>` token to `e` — ARP
// stimulus knobs that steer a case rather than gate its verdict (never
// guard-compared; see `ArpStimulusConfig`). The `arp_stimulus.` prefix and key
// set are the SSOT in tc8_expect_keys.def. Returns false when the token lacks
// the prefix, the value fails its parser, or the post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::ArpStimulusConfig &e);

// Applies a single `--expect icmpv4.<key>=<value>` token to `e`. The `icmpv4.`
// prefix and key set are the SSOT in tc8_expect_keys.def. Semantic note:
// `echo_id`/`echo_seq` are *expectations* the §4.3.3.2 TYPE_09 SCXML guard
// compares against; the tester stimulus hardcodes the matching literals
// (`stimulus/icmpv4_builder.h::kIcmpEchoId`/`kIcmpEchoSeq`), so `--negative`
// can flip these without shifting what the tester sends. Returns false when
// the token lacks the prefix, the value fails its parser, or the key is
// unknown.
bool applyExpectToken(std::string_view token, ::tc8::Icmpv4Expectations &e);

// Applies a single `--expect ipv4.<key>=<value>` token to `e`. The `ipv4.`
// prefix and key set are the SSOT in tc8_expect_keys.def. Semantic notes:
// `dut_iface_ip` is the §4.4 `dispatch()` source-filter (only DUT-originated
// frames drive the state machine) and HEADER_03's pass-guard comparand;
// `tester_ip` is carried for symmetry with `Icmpv4Expected` and future
// §4.4.4.2 symmetric checks (no current §4.4 guard reads it). Returns false
// when the token lacks the prefix, the value fails `parseIpv4Dotted`, or the
// post-prefix key is unknown.
bool applyExpectToken(std::string_view token, ::tc8::Ipv4Expectations &e);

// Applies a single `--expect dhcpv4.<key>=<value>` token to `e`. The `dhcpv4.`
// prefix and key set are the SSOT in tc8_expect_keys.def. Semantic note:
// `dut_iface_mac` is the *expectation* §4.7 passive-observation cases gate on
// (`captured.chaddr_matches_dut_mac(...)`) so ambient non-DUT DHCP traffic does
// not drive verdicts. Returns false when the token lacks the prefix, the value
// fails its parser, or the post-prefix key is unknown.
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
