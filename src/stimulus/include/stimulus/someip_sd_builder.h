#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tc8/someip/sd_wire_constants.h"  // sd_flags::kRebootUnicast — SD header flags SSOT.
#include "stimulus/boot_timing.h"
#include "tc8/dut_config.h"  // kSdPort / kSdMcastGroup — SD port/group SSOT.

namespace tc8::stimulus {

// Target identity of a FindService — the "what we're looking for" half of
// SOME/IP-SD TR_SOMEIP §7.3 FindService semantics. Session ID and SD flags are not
// part of the target (they belong to the emit cadence) and are set by
// the low-level `FindServiceParams` or the high-level `emitFindServiceBoot`.
struct FindServiceTarget {
    std::uint16_t service_id = 0xF4E7;          // SERVICE-ID-1 (tc8-dut default)
    std::uint16_t instance_id = 0xFFFF;         // 0xFFFF = any instance
    std::uint8_t major_version = 0xFF;          // 0xFF = any major version
    std::uint32_t ttl = 3;                      // seconds
    std::uint32_t minor_version = 0xFFFFFFFFu;  // 0xFFFFFFFF = any minor version
};

// Full parameters for a single FindService datagram — target identity
// plus the emit-state fields. Used by the low-level `buildFindService`
// when callers want full control over one emit; `emitFindServiceBoot`
// computes these internally across a retry sequence.
struct FindServiceParams {
    FindServiceTarget target{};

    // SD Session ID for this FindService. Starts at 0x0001 per SD §4.2.1
    // and mirrors FORMAT_02's requirement on the DUT side.
    std::uint16_t session_id = 0x0001;

    // Reboot=1 Unicast=1 until Session ID wraps 0xFFFF -> 0x0000 per SD §4.2.1;
    // drops to Unicast-only (sd_flags::kUnicast) only after the wrap.
    std::uint8_t sd_flags = ::tc8::sd_flags::kRebootUnicast;

    // SD header 24-bit Reserved field (the 3 bytes after the Flags byte).
    // Canonically 0; a case sets non-zero bits to verify the DUT ignores
    // undefined Reserved bits in a FindService SD header per the SOME/IP-SD
    // reserved-handling requirement (PRS_SOMEIPSD_00307). Must fit in 24 bits
    // (the field is 3 bytes); putBe24 asserts otherwise. The sibling Offer/Subscribe SD builders
    // hardcode their Reserved field to 0 — give their Params the same override
    // when a case needs to flip THEIR Reserved bits (no shared field yet, by
    // YAGNI: FindService is the only current consumer).
    std::uint32_t sd_reserved = 0;
};

// Timing envelope for the tester-side SD boot sequences lives in
// `stimulus/boot_timing.h` (`BootTiming`) — shared with the UT
// OpTriggerSendUdp boot emitter in `stimulus/upper_tester_client.h`.

// Builds the 44-byte SOME/IP-SD FindService datagram payload (16-byte
// SOME/IP header + 28-byte SD payload with one FindService entry and no
// options). The returned bytes are the UDP payload — caller is responsible
// for the UDP/IP/Ethernet encapsulation (handled by the kernel when
// sendto() goes through a normal UDP socket).
std::vector<std::uint8_t> buildFindService(const FindServiceParams &p);

// Transmits `datagram` as a UDP multicast to `mcast_group`:`mcast_port`
// over the interface `iface_name` (e.g. "veth-tester"). Uses IP_MULTICAST_IF
// with the interface address so we don't depend on the default route
// picking the right leg of the veth pair.
//
// Returns 0 on success, a negative value on failure (errno is logged to
// stderr). The socket is opened, used once, and closed — stimulus is a
// one-shot action in the current harness.
int sendSdMulticast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                    std::string_view mcast_group = tc8::dut::kSdMcastGroup,
                    std::uint16_t mcast_port = tc8::dut::kSdPort);

// Raw-L2 sibling of sendSdMulticast for cases that must drive an SD multicast
// (FindService / OfferService) FROM a spoofed source IP — e.g. two ECUs that the
// DUT must discriminate by Sender IP. sendSdMulticast
// is kernel-sourced (a socket bound to the iface IP), so it cannot spoof the
// source; this builds the full Ethernet+IPv4+UDP frame with `src_ip_be` as the
// IPv4 source and the RFC 1112 IPv4-multicast destination MAC for `mcast_group`
// (`ipv4MulticastMac`, 01:00:5e | low 23 bits) and injects it via
// `sendUdpFromSourceIp` (AF_PACKET, CAP_NET_RAW). The source port is the SD port
// (= `mcast_port`) so vsomeip's "SD source port must equal SD port" check accepts
// the Find, exactly as sendSdMulticast does.
//
// `src_mac` is the Ethernet source advertised on the frame; it MUST equal the
// `mac` of the `ArpResponder` binding armed for `src_ip_be` so the DUT's unicast
// Offer to the spoofed IP returns to a MAC the tester is on — source both from
// `macOfInterface(iface)`. The default `{}` (zero) is valid only for veth/netns
// capture, where pcap sees the Offer regardless of its L2 destination; a real DUT
// needs the real tester MAC. Returns 0 on success, -5 if `mcast_group` is
// malformed, or the negative `sendUdpFromSourceIp` / `sendRawEthernet` sentinel.
int sendSdMulticastFromSourceIp(const std::vector<std::uint8_t> &datagram, std::string_view iface,
                                std::uint32_t src_ip_be,
                                const std::array<std::uint8_t, 6> &src_mac = {},
                                std::string_view mcast_group = tc8::dut::kSdMcastGroup,
                                std::uint16_t mcast_port = tc8::dut::kSdPort);

// Transmits `datagram` as a UDP unicast to `dst_ip_be`:`dst_port` over
// `iface_name`. Source port is bound to the SD port (30490) so vsomeip's
// "SD source port must equal SD port" check accepts the message; without
// this the DUT logs `Ignored SD message from unknown port (NNNNN)` and
// drops it. Used by §5.1.5.4 SD_BEHAVIOR_03 (Find with Unicast Flag=1
// addressed to the DUT's SD endpoint, which the DUT answers with a
// multicast OfferService when the last cyclic Offer was > 1/2 CYCLIC ago).
//
// `dst_ip_be` is a 32-bit IPv4 address in network byte order (matches
// `SubscribeDestination::ipv4_be` semantics). Returns 0 on success or a
// negative errno-derived sentinel on failure.
int sendSdUnicast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                  std::uint32_t dst_ip_be, std::uint16_t dst_port = tc8::dut::kSdPort);

// High-level TESTER boot-time FindService emit sequence used by §5.1
// stimulus-driven cases (FORMAT_12/13). Waits for the DUT to come up,
// then sends `timing.total_emits` FindService datagrams, incrementing
// the SD Session ID (0x0001, 0x0002, ...) and keeping Reboot=1 for the
// entire pre-wrap run per SD §4.2.1.
//
// Blocks the calling thread for the full `timing` envelope. Returns 0
// if every emit succeeded, or the first negative return from
// `sendSdMulticast` on any failure (no retry-on-failure — the cadence
// is fixed so higher layers can reason about total wall time).
int emitFindServiceBoot(std::string_view iface, const FindServiceTarget &target = {}, const BootTiming &timing = {});


// Tester endpoint advertised inside a SubscribeEventgroup's IPv4 Endpoint
// option (SD TR_SOMEIP §7.4.3). The DUT Ack/Nack is sent back to this address:port
// on UDP. `ipv4_be` is stored in network byte order (what sendto() wants
// and what the option-array encoder streams onto the wire without swap).
struct Ipv4Endpoint {
    std::uint32_t ipv4_be = 0;
    std::uint16_t port = 0;
    std::uint8_t l4proto = 0x11;  // 0x11 UDP, 0x06 TCP — subscribe uses UDP.
};

// One extra SOME/IP-SD option appended to an Options Array. Wire shape:
//   Length(2B BE) | Type(1B) | Reserved(1B) | body
// `body` is the bytes AFTER the Reserved byte (the Discardable flag lives in the
// Reserved byte's MSB). The Length FIELD value is not carried here — the emitting
// builder writes it via the appendSdExtraOption SSOT as Length = 1 + body.size()
// (counting the Reserved byte, spec-correct and matching appendIpv4EndpointOption /
// appendConfigurationOption / the sd_decode.h option walk opt_total = 3 + Length).
// Shared by the OfferService (buildOfferServiceWithEndpoint) and Subscribe
// (buildSubscribeEventgroup) paths — one struct, one encoder, one Length convention.
struct SdExtraOption {
    std::uint8_t type;
    std::vector<std::uint8_t> body;   // bytes after the Reserved byte
    std::uint8_t reserved = 0;        // Discardable flag lives in this byte's MSB
};

// Body of an IPv4 Endpoint (0x04) / IPv4 Multicast (0x14) / IPv4 SD Endpoint (0x24)
// option — the bytes AFTER the option's Reserved byte: IPv4 address (4B, network
// order streamed LSB-first) + Reserved(1B) + L4-Proto(1B) + Port(2B BE), i.e. 8 bytes.
// The single encoder for that body: appendIpv4EndpointOption prefixes Length(9) + Type
// + Reserved around it, and a case building a duplicate / conflicting / multicast
// endpoint as an SdExtraOption reuses it (its Length becomes 1 + 8 = 9). Keeps the
// endpoint-body layout spelled exactly once.
std::vector<std::uint8_t> sdIpv4OptionBody(const Ipv4Endpoint &ep);

// §5.1.6 SOMEIP_ETS_118 helper: 56-byte FindService carrying one UNREFERENCED
// IPv4 Endpoint option (#Opt1=0) in its Options Array — the option is physically
// present but the DUT must ignore it per PRS_SOMEIPSD_00268 / SIP_SD_877 /
// SIP_SD_878 and still respond with at least one OfferService.
std::vector<std::uint8_t> buildFindServiceWithOption(const FindServiceParams &p,
                                                     const Ipv4Endpoint &endpoint);

// 56-byte FindService carrying one REFERENCED (#Opt1=1) Type-0x24 IPv4 SD
// Endpoint option: a DUT that honours the referenced endpoint option answers the
// Find to `endpoint` (address / L4-proto / port) rather than to the SD sender.
// Same wire shape as buildFindServiceWithOption apart from the option type byte
// and the referenced option-run nibble.
std::vector<std::uint8_t> buildFindServiceWithReferencedSdEndpointOption(const FindServiceParams &p,
                                                                         const Ipv4Endpoint &endpoint);

// TTL (seconds) an observe-and-verify Subscribe uses to OUTLAST the capture
// window, so the subscription stays active while the case observes the DUT's
// Ack and events. Cases asserting subscription EXPIRY set a short `target.ttl`
// instead. Single source for the "outlast" value across the eg-subscribe cases.
inline constexpr std::uint32_t kSubscribeOutlastTtl = 16;

// Target identity of a SubscribeEventgroup — the eventgroup we're asking
// the DUT to publish to us. Session ID / SD flags / tester endpoint are
// set by `emitSubscribeEventgroupBoot`; this struct is the "what to
// subscribe to" half.
struct SubscribeEventgroupTarget {
    std::uint16_t service_id = 0xF4E7;     // SERVICE-ID-1 (tc8-dut default)
    std::uint16_t instance_id = 0x0001;    // SERVICE-ID-1-INSTANCE-ID
    std::uint16_t eventgroup_id = 0x0001;  // SdConsumedEventGroupID
    std::uint8_t major_version = 1;
    std::uint32_t ttl = 3;        // seconds
    std::uint8_t counter = 0;     // 4-bit subscribe counter (TR_SOMEIP §7.1.3)
    // 12-bit Reserved field of the SubscribeEventgroup entry (bytes 12-13,
    // sharing the 16-bit word with the 4-bit counter above). Default unset →
    // spec-canonical 0. A case sets specific reserved bits to drive an
    // implementation-defined entry flag (e.g. an Initial-Data-Requested bit a
    // DUT's deployment locates here); the harness stays neutral on the meaning.
    std::optional<std::uint16_t> entry_reserved;
};

// Full parameters for one SubscribeEventgroup datagram — target identity
// plus the tester's endpoint (carried in the IPv4 Endpoint option) and
// the emit-state fields. Used by the low-level `buildSubscribeEventgroup`.
//
// Wire-shape overrides used by §5.1.6 SOMEIP_ETS_123..144 to inject
// malformed Subscribe variants the DUT must reject (Nack) or ignore:
//   - `entries_len_override`     overrides EntriesLen (canonical 16).
//     _123 sets a value far exceeding SOME/IP Length (e.g. 0xFFFFFF00),
//     _124 sets a value ≥20 larger than the actual entry bytes (e.g. 36),
//     _125 sets a value smaller than one Type 2 entry needs (e.g. 8).
//   - `length_override`          overrides the SOME/IP Length field
//     (canonical 48 for one entry + one option). _134 cuts it by 12 to
//     simulate a truncated SD message.
//   - `options_len_override`     overrides OptionsLen (canonical 12 for
//     one IPv4 Endpoint option). _134 cuts to 0; _135/_139 set values
//     smaller than the actual option bytes; _138 sets larger.
//   - `option_body_len_override` overrides the IPv4 Endpoint option's
//     own Length field (canonical 9). _136 sets to 4 (less than spec
//     requires for the option type).
//   - `option_reserved0/1_override` flip the two reserved bytes inside
//     the IPv4 Endpoint option (canonical 0). _144 sets non-zero to
//     verify the DUT ignores reserved fields per PRS_SOMEIPSD_00307.
struct SubscribeEventgroupParams {
    SubscribeEventgroupTarget target{};
    Ipv4Endpoint tester_endpoint{};
    // Optional SECOND IPv4 Endpoint option (canonical 12-byte shape, emitted
    // via the appendIpv4EndpointOption SSOT right after `tester_endpoint` and
    // before any raw `extra_options`). Default unset → single-option Subscribe,
    // byte-identical to before. Set it — together with
    // `num_options_first_override = 2` so the Type-2 entry's first option run
    // references BOTH options — for the dual-transport (UDP + TCP) Subscribe the
    // reference emits to a mixed-reliability (RT_BOTH) eventgroup: vsomeip NACKs
    // a single-option Subscribe to such an eventgroup, requiring one UDP and one
    // TCP endpoint option. `setDualEndpointSubscribe` wires both in one call.
    std::optional<Ipv4Endpoint> second_endpoint;
    std::uint16_t session_id = 0x0001;
    std::uint8_t sd_flags = ::tc8::sd_flags::kRebootUnicast;  // same cadence as FindService
    std::uint32_t entries_len_override = 0;  // 0 → canonical 16; non-zero overrides EntriesLen.
    std::optional<std::uint32_t> length_override;
    std::optional<std::uint32_t> options_len_override;
    std::optional<std::uint16_t> option_body_len_override;
    std::optional<std::uint8_t> option_reserved0_override;
    std::optional<std::uint8_t> option_reserved1_override;
    // §5.1.6 SOMEIP_ETS_116/_174 helper: override the IPv4 Endpoint option's
    // Type byte (canonical 0x04). Setting a non-default value (e.g. 0x77)
    // exercises the DUT's "unknown option type" path per PRS_SOMEIPSD_00273
    // / 00305 — DUT must Nack or ignore.
    std::optional<std::uint8_t> option_type_override;
    // §5.1.6 SOMEIP_ETS_178 helper: override the SOME/IP header Method ID
    // field (canonical 0x8100 for SD). A non-SD method ID makes the
    // DUT's parser reject the message as not a valid SOME/IP-SD payload
    // per PRS_SOMEIPSD_00306 / 00307 / 00380 / 00393.
    std::optional<std::uint16_t> method_id_override;
    // §5.1.6 SOMEIP_ETS_115 helper: override the #Opt1 nibble (high 4 bits
    // of byte 3 of the Type 2 entry — canonical 1, "one option in run 1").
    // Setting a value greater than the actual options array population
    // exercises the DUT's "more option references than exist" path per
    // PRS_SOMEIPSD_00393 / 00566.
    std::optional<std::uint8_t> num_options_first_override;
    // §5.1.6 SOMEIP_ETS_176 / _177 helpers: append `extra_trailing_payload`
    // bytes after the Options Array. When `extra_trailing_in_length` is
    // true (canonical for _176 phase 1) the SOME/IP Length field counts
    // the trailing bytes; when false (_176 phase 2 + _177) the length
    // field stays at the canonical 48 so the trailing bytes are physically
    // on-wire but not counted. Per PRS_SOMEIPSD_00153 / 00273 the DUT must
    // still Ack the Subscribe (extra payload is ignored).
    std::vector<std::uint8_t> extra_trailing_payload;
    bool extra_trailing_in_length = true;
    // §5.1.6 SOMEIP_ETS_117 / _173 / _175 helpers: index / count overrides
    // for the Type 2 entry's option-run fields (canonical: index1=0,
    // index2=0, #Opt2=0). _173 phase 1 uses index2=1 + #Opt2=1 to point
    // run 2 at the second extra option; _173 phase 2 uses #Opt1=2 to
    // reference both options via run 1.
    std::optional<std::uint8_t> index_first_options_override;
    std::optional<std::uint8_t> index_second_options_override;
    std::optional<std::uint8_t> num_options_second_override;
    // §5.1.6 SOMEIP_ETS_175 helper: extra options appended after the canonical IPv4
    // Endpoint option (and any `second_endpoint`), each contributing 4 + body.size()
    // bytes (Length 2B BE + Type 1B + Reserved 1B + body) to the Options Array via the
    // appendSdExtraOption SSOT. OptionsLen and SOME/IP Length auto-extend by the total
    // unless `options_len_override` / `length_override` are set. _175 appends one
    // unreferenced Configuration Option (Type 0x01). The element type is the shared
    // `SdExtraOption`; the option Length is spec-correct (counts the Reserved byte),
    // identical to the OfferService path.
    using ExtraSdOption = SdExtraOption;
    std::vector<ExtraSdOption> extra_options;
};

// Builds the 56-byte SOME/IP-SD SubscribeEventgroup datagram payload
// (16-byte SOME/IP header + 40-byte SD payload: 4B flags/reserved +
// 4B EntriesLen + 16B Type 2 entry + 4B OptionsLen + 12B IPv4 Endpoint
// option). Unlike `buildFindService` (no options), subscribe references
// exactly one option — the tester's UDP endpoint where the DUT Ack/Nack
// is to be sent. Caller is responsible for UDP/IP/Ethernet encapsulation.
std::vector<std::uint8_t> buildSubscribeEventgroup(const SubscribeEventgroupParams &p);

// Configure `p` for a dual-transport (UDP + TCP) SubscribeEventgroup: set the
// second IPv4 Endpoint option to `tcp_endpoint` (l4proto forced to TCP 0x06) and
// point the Type-2 entry's first option run at BOTH options (#Opt1 = 2). Option 0
// stays `p.tester_endpoint` (the UDP endpoint; leave its ipv4_be zero so
// emitSubscribeEventgroupRaw fills it from the iface). This is the reference's
// Subscribe shape for a mixed-reliability (RT_BOTH) eventgroup, which vsomeip
// NACKs unless the Subscribe carries one UDP and one TCP endpoint option. Both
// options are emitted through the appendIpv4EndpointOption SSOT, so cases no
// longer hand-encode the second option's bytes.
void setDualEndpointSubscribe(SubscribeEventgroupParams &p, const Ipv4Endpoint &tcp_endpoint);

// Destination of a SubscribeEventgroup datagram — the DUT's SD unicast
// endpoint (SD §4.2: Subscribe is sent unicast to the server's SD
// address, not multicast). Default matches the tc8-dut bundled in this
// repo (172.16.0.2 : 30490); real DUTs override via the emitter param.
struct SubscribeDestination {
    // IPv4 in network byte order (byte-order semantics match
    // `Ipv4Endpoint::ipv4_be`).
    //
    // 0 means "the DUT this run targets" and is resolved from the site identity
    // the runner publishes (`tc8::stimulus::siteDutIpv4()`, fed from
    // `TestConfig::dut.ip`) — the same 0-means-derive idiom this file already
    // uses for the tester's own endpoint. A case that must address something
    // OTHER than the DUT sets the field.
    //
    // This used to default to the literal 172.16.0.2, the reference DUT's
    // address inside the single-pc netns. That made every case pass on netns —
    // where the literal IS the DUT — and silently mis-address the Subscribe on
    // any real two-machine site, where it fell through to the default route.
    // A default that is correct in exactly one topology is a trap, not a
    // default; the sentinel makes the run supply the answer.
    std::uint32_t ipv4_be = 0;
    std::uint16_t port = tc8::dut::kSdPort;
};

// High-level TESTER boot-time SubscribeEventgroup emit sequence used by
// §5.1 FORMAT_19..28. Waits for the DUT to come up, then for each emit
// opens a fresh UDP socket bound to an ephemeral port on `iface`,
// advertises that port inside the SD IPv4 Endpoint option, and sends a
// SubscribeEventgroup unicast to the DUT's SD endpoint. Session ID
// increments per emit; SD Reboot=1 stays set for the entire pre-wrap
// run per SD §4.2.1.
//
// The build-and-send step lives on a single socket so the port embedded
// in the option always matches the actual source port the DUT sees —
// otherwise the Ack would be routed to a port nothing is listening on.
//
// Blocks the calling thread for the full `timing` envelope. Returns 0
// on success or the first negative return from the underlying send
// logic.
int emitSubscribeEventgroupBoot(std::string_view iface, const SubscribeEventgroupTarget &target = {},
                                const BootTiming &timing = {}, const SubscribeDestination &dest = {});

// §5.1.6 SOMEIP_ETS_096 helper: emit boot-time SubscribeEventgroup whose
// IPv4 Endpoint option declares l4proto = 0x06 (TCP) instead of 0x11
// (UDP) WITHOUT pre-establishing a TCP connection to the advertised
// endpoint. Per PRS_SOMEIPSD_00362 the DUT must reply with a
// SubscribeEventgroupNack (Type 0x07 entry, ttl == 0) for any Subscribe
// referencing a TCP transport that has no live connection.
//
// Same blocking + cadence semantics as `emitSubscribeEventgroupBoot`;
// only the option's `l4proto` byte differs on the wire.
int emitSubscribeEventgroupBootTcpOption(std::string_view iface, const SubscribeEventgroupTarget &target = {},
                                         const BootTiming &timing = {}, const SubscribeDestination &dest = {});

// §5.1.6 SOMEIP_ETS_093 helper: emit one SubscribeEventgroup with the
// caller's exact `session_id` + `sd_flags` (no boot cadence). Tester
// endpoint advertised in the option is the iface IPv4 + SD port (30490);
// caller controls per-subscribe session-id semantics so the DUT-side
// reboot tracker can be exercised across pre-/post-reboot transitions.
// Returns 0 on success or a negative errno-derived sentinel on failure.
int emitSubscribeEventgroupOnce(std::string_view iface,
                                const SubscribeEventgroupTarget &target,
                                std::uint16_t session_id,
                                std::uint8_t sd_flags = ::tc8::sd_flags::kRebootUnicast,
                                std::uint8_t l4proto = 0x11,
                                const SubscribeDestination &dest = {});

// §5.1.6 SOMEIP_ETS_123/_124/_125 helper: emit one SubscribeEventgroup
// using a caller-controlled SubscribeEventgroupParams (so EntriesLen can
// be corrupted via `entries_len_override`). Same socket lifecycle as
// `emitSubscribeEventgroupOnce` (UDP socket bound to SD port 30490 with
// SO_REUSEADDR); tester endpoint advertised in the option auto-derives
// from the iface IPv4 + SD port unless caller pre-fills `tester_endpoint`.
// Returns 0 on success or a negative errno-derived sentinel on failure.
// `source_ip_be` (network byte order; 0 = the iface primary) sets the SOURCE IP of
// the Subscribe datagram — not just the option's advertised endpoint — so a second
// client on a configured alias IP is a DISTINCT SD sender the DUT tracks as its own
// subscription (vsomeip keys a remote subscription by the SD sender; two Subscribes
// from one source IP collapse to one). Used to originate a second reliable client.
int emitSubscribeEventgroupRaw(std::string_view iface,
                               SubscribeEventgroupParams params,
                               const SubscribeDestination &dest = {},
                               std::uint32_t source_ip_be = 0);

// §5.1.6 SOMEIP_ETS_098/_101 helper: tester-side OfferService /
// StopOfferService for SERVICE-ID-2 (the DUT's Client-Mode target). The
// DUT firmware's ClientModeRunner does NOT listen for inbound SD packets
// — the DUT-side reaction is "burst then idle" by design — so the
// `OfferServiceTarget.ttl` field is decorative for the current cluster.
// Future cases that grow the DUT firmware to react to StopOfferService
// (per PRS_SOMEIPSD_00363) will tighten the verdict shape; this builder
// is the wire-correct stimulus they will share.
struct OfferServiceTarget {
    std::uint16_t service_id    = 0xF4E8;          // SERVICE-ID-2 (Client-Mode target).
    std::uint16_t instance_id   = 0x0001;
    std::uint8_t  major_version = 0x01;
    // ttl > 0 = OfferService; ttl == 0 = StopOfferService per SD §4.2.
    std::uint32_t ttl           = 3;
    std::uint32_t minor_version = 0;
    std::uint16_t session_id    = 0x0001;
    // SD Flags byte (Reboot bit7 | Unicast bit6). Default kRebootUnicast = the
    // canonical post-boot Offer. A server-role case overrides the Reboot flag (e.g.
    // sd_flags::kUnicast alone, Reboot=0) so the DUT's reboot-detection tracker is
    // exercised across an Offer stream; the session_id above is the matching
    // counter (TR_SOMEIP §4.2.1 reboot semantics).
    std::uint8_t  sd_flags      = ::tc8::sd_flags::kRebootUnicast;
    // SD header 24-bit Reserved field (the 3 bytes after the Flags byte). Canonically
    // 0; a case sets non-zero bits to verify a receiver ignores undefined Reserved bits
    // per PRS_SOMEIPSD_00307 — the OfferService mirror of FindServiceParams::sd_reserved.
    // Passed through by every OfferService builder (buildOfferService and the
    // *WithEndpoint* family). Must fit in 24 bits (putBe24 asserts otherwise).
    std::uint32_t sd_reserved   = 0;
};

// 44-byte SOME/IP-SD OfferService datagram (16-byte SOME/IP header + 28-byte
// SD payload with one Type-0x01 entry, no options array). Same shape as
// `buildFindService` with the entry type flipped to 0x01 (Offer/Stop) and
// the entry's TTL field consulted for the Offer-vs-Stop discriminator.
std::vector<std::uint8_t> buildOfferService(const OfferServiceTarget &t);

// One-shot multicast emit for `target`. Sleeps `pre_emit_wait` first so the
// caller can chain after `emitFindServiceBoot` / `emitMethodRequestAfter`.
// Returns 0 on success or the negative `sendSdMulticast` return on failure.
int emitOfferServiceMulticast(std::string_view iface,
                              const OfferServiceTarget &target = {},
                              std::chrono::milliseconds pre_emit_wait =
                                  std::chrono::milliseconds(500));

// §5.1.6 SOMEIP_ETS_097 helper — OfferService carrying one IPv4 Endpoint
// Option that advertises the tester's L4 endpoint (TCP for ETS_097 per
// PRS_SOMEIPSD_00362). The wire shape is 56 B = 16 B SOME/IP + 4 B SD flags
// + 4 B EntriesLen + 16 B Type 0x01 entry (referencing one option) + 4 B
// OptionsLen + 12 B IPv4 Endpoint option. SOME/IP Length field = 48.
// Reusable for any future case that needs OfferService with one endpoint.
struct OfferServiceWithEndpointTarget {
    OfferServiceTarget service{};   // Identity, ttl, session_id.
    Ipv4Endpoint       endpoint{};  // Tester's L4 endpoint advertised in Option run 1.
    // Extra options the ENTRY references in addition to the mandatory data endpoint:
    // #Opt1 becomes 1 + extra_options.size(), and OptionsLen / SOME/IP Length grow to
    // match. Default empty → byte-identical to the single-option Offer. A client-role
    // case injects a redundant / not-required / unknown-type / conflicting referenced
    // option a receiver must ignore or reject; build an endpoint/multicast body via
    // `sdIpv4OptionBody` so the encoder stays shared. Honoured ONLY by
    // buildOfferServiceWithEndpoint — the *AndSdEndpointOption / *AndConfigOption
    // builders carry their own fixed second option and ignore this field.
    std::vector<SdExtraOption> extra_options;
};

std::vector<std::uint8_t>
buildOfferServiceWithEndpoint(const OfferServiceWithEndpointTarget &t);

// 68-byte OfferService that redirects a DUT client's SubscribeEventgroup to a
// separate SD endpoint: options[0] is a Type-0x24 IPv4 SD Endpoint option (the
// redirect target `sd_ep`, which a DUT client reads at message level) and options[1]
// is a Type-0x04 IPv4 Endpoint option (the service data endpoint `data_ep.endpoint`,
// which the entry references). Unlike a FindService (a query with no endpoint), an
// OfferService WITHOUT a data endpoint is dropped as an unknown offer — so the
// redirect Offer must carry BOTH options. A pure builder with no emit companion:
// emit via `sendSdUnicast` or `sendSdMulticastFromSourceIp`.
std::vector<std::uint8_t>
buildOfferServiceWithEndpointAndSdEndpointOption(const OfferServiceWithEndpointTarget &data_ep,
                                                 const Ipv4Endpoint &sd_ep);

// Encode a SOME/IP-SD Configuration option BODY (the bytes after the option's
// Reserved byte): length-prefixed "key=value" items terminated by a zero-length
// byte — `[len1]key1=value1 [len2]key2=value2 ... 0x00`, each length byte counting
// `key + '=' + value` (which must be <= 255). This is the single source for the
// config-string shape, shared by `buildOfferServiceWithEndpointAndConfigOption` and
// by any Subscribe/Ack case that references a config option via `ExtraSdOption::body`.
std::vector<std::uint8_t>
encodeSdConfigOptionBody(const std::vector<std::pair<std::string, std::string>> &items);

// OfferService carrying TWO entry-referenced options: options[0] is a Type-0x04
// IPv4 Endpoint option (the service data endpoint `data_ep.endpoint`) and
// options[1] is a Type-0x01 Configuration option holding `config_items`. The
// entry references BOTH (IndexFirstOptionRun=0, #Opt1=2). The data endpoint is
// mandatory here for the same reason as `buildOfferServiceWithEndpointAndSdEndpointOption`
// — an OfferService without a data endpoint is dropped as an unknown offer.
//
// Unlike an endpoint option, a Configuration option is delivered to the receiving
// application ONLY when the service entry references it: the reference SOME/IP-SD
// receiver walks the entry's option runs (`get_options`) and an unreferenced option
// in the array is never visited. Hence #Opt1=2 rather than leaving the config
// option unreferenced.
//
// Each item is encoded per SOME/IP-SD OPTIONS Configuration-Option shape as
// `[len][key '=' value]`, length-prefixed with a single byte (so `key + 1 + value`
// must be <= 255), followed by a zero-length terminator byte. A pure builder with
// no emit companion: emit via `sendSdUnicast` / `sendSdMulticastFromSourceIp`.
std::vector<std::uint8_t>
buildOfferServiceWithEndpointAndConfigOption(const OfferServiceWithEndpointTarget &data_ep,
                                             const std::vector<std::pair<std::string, std::string>> &config_items);

int emitOfferServiceMulticastWithEndpoint(std::string_view iface,
                                          const OfferServiceWithEndpointTarget &t,
                                          std::chrono::milliseconds pre_emit_wait =
                                              std::chrono::milliseconds(500));

// Multiple Type-1 OfferService entries in one SD message, all referencing one shared
// IPv4 Endpoint option (run 0 → option index 0, #Opt1=1 per entry) — the OfferService
// parallel of buildMultiSubscribeEventgroup. A receiver processes every entry in the
// array in order (SOMEIPSD entry-array semantics). Per-entry Service/Instance/Major/
// TTL/Minor live in each OfferServiceTarget; the SD header session/flags/reserved are
// the message-level fields below (the per-entry header fields on each OfferServiceTarget
// are header-level, so — like buildMultiSubscribeEventgroup — the multi-entry builder
// ignores them). A pure builder with no emit companion: emit via sendSdMulticast /
// sendSdUnicast / sendSdMulticastFromSourceIp.
struct MultiOfferServiceParams {
    std::vector<OfferServiceTarget> entries;   // one Type-1 OfferService entry each
    Ipv4Endpoint  endpoint{};                  // the shared data endpoint every entry references
    std::uint16_t session_id  = 0x0001;
    std::uint8_t  sd_flags    = ::tc8::sd_flags::kRebootUnicast;
    std::uint32_t sd_reserved = 0;
};

std::vector<std::uint8_t> buildMultiOfferService(const MultiOfferServiceParams &p);

// §5.1.6 SOMEIP_ETS_088 helper: SD message carrying multiple Type 2
// SubscribeEventgroup entries, all sharing one option run 0
// (single IPv4 Endpoint option). Each entry's eventgroup_id / ttl
// / counter / etc. lives in its own SubscribeEventgroupTarget. The
// DUT walks the entries one at a time and emits Ack/Nack for each
// per SD §4.2 (PRS_SOMEIPSD_00263).
struct MultiSubscribeEventgroupParams {
    std::vector<SubscribeEventgroupTarget> entries;
    Ipv4Endpoint tester_endpoint{};
    // Optional second IPv4 Endpoint option (TCP) for a bundle that includes a
    // mixed-reliability eventgroup (e.g. eg 0x0002 carrying reliable 0x8003):
    // when set it is emitted as option 1 (canonical 12B) and every entry
    // references BOTH options (#Opt1=2). The subscriber must hold an established
    // connection to the advertised TCP endpoint (SubscribeEventgroupTcpSession)
    // or vsomeip NACKs the mixed entry. Unset (default) keeps the single-option
    // bundle byte-identical to before.
    std::optional<Ipv4Endpoint> second_endpoint;
    // Per-entry #Opt1 (option references in the entry's first run). When set,
    // entry i references `per_entry_num_options_first[i]` options from index 0
    // (1 = the UDP option only, for an unreliable eventgroup; 2 = UDP + TCP, for
    // a mixed one). Empty (default) → every entry references both when
    // second_endpoint is set, else the single UDP option. Lets a bundle mix a
    // mixed-reliability eventgroup (dual) with unreliable ones (UDP-only), as the
    // reference does, instead of binding the unreliable entries reliably too.
    std::vector<std::uint8_t> per_entry_num_options_first;
    std::uint16_t session_id = 0x0001;
    std::uint8_t sd_flags = ::tc8::sd_flags::kRebootUnicast;
    // §5.1.6 SOMEIP_ETS_114 helper: override the EntriesLen field. Default
    // (0) means "auto-compute from entries.size() * 16". Non-zero overrides
    // to inject malformed entries-array-length values per
    // PRS_SOMEIPSD_00264 / 00265 / 00393.
    std::uint32_t entries_len_override = 0;
};

std::vector<std::uint8_t>
buildMultiSubscribeEventgroup(const MultiSubscribeEventgroupParams &p);

// Single-shot multi-entry Subscribe emit. Caller is responsible for
// having driven SD up first (e.g. via emitFindServiceBoot). Sleeps
// `pre_emit_wait`, opens a UDP socket bound to the SD port (vsomeip
// drops SD packets from ephemeral source ports), sends the bundle,
// closes. Returns 0 on success, negative on failure.
int emitMultiSubscribeEventgroup(std::string_view iface,
                                 const std::vector<SubscribeEventgroupTarget> &entries,
                                 std::chrono::milliseconds pre_emit_wait =
                                     std::chrono::milliseconds(500),
                                 const SubscribeDestination &dest = {});

// §5.1.6 SOMEIP_ETS_114 raw helper: emit a multi-entry Subscribe with full
// MultiSubscribeEventgroupParams control (so `entries_len_override` can
// inject a malformed entries-array-length). Same socket lifecycle as
// `emitMultiSubscribeEventgroup`; tester endpoint advertised in the option
// auto-derives from the iface IPv4 + SD port unless caller pre-fills
// `tester_endpoint`. Returns 0 on success or a negative errno-derived
// sentinel on failure.
int emitMultiSubscribeEventgroupRaw(std::string_view iface,
                                    MultiSubscribeEventgroupParams params,
                                    std::chrono::milliseconds pre_emit_wait =
                                        std::chrono::milliseconds(500),
                                    const SubscribeDestination &dest = {});

// --- Tester SERVER-role SD answer surface (client-role topology) ---
//
// In the SERVER-role (tester-offers, DUT-subscribes) topology the DUT issues a
// SubscribeEventgroup and the tester must answer with a SubscribeEventgroupAck
// (TR_SOMEIP §7.4.2 SD entry type 0x07). There is no separate Nack entry type:
// TTL > 0 is the Ack, TTL == 0 is the Nack — the TTL discriminates, exactly as
// `buildOfferService` uses TTL for Offer vs StopOffer. Build the answer from the
// captured Subscribe's identity so the DUT correlates it (echo
// Service/Instance/Major/Eventgroup/Counter), and target the captured client's
// own SD endpoint.

// Identity of a SubscribeEventgroupAck/Nack entry — the "what we are answering"
// half. Mirrors `SubscribeEventgroupTarget`, with TTL carrying the Ack/Nack
// discriminator and an optional multicast delivery endpoint.
struct SubscribeEventgroupAckTarget {
    std::uint16_t service_id = 0xF4E7;     // SERVICE-ID-1 (echo the Subscribe).
    std::uint16_t instance_id = 0x0001;
    std::uint16_t eventgroup_id = 0x0001;
    std::uint8_t major_version = 1;
    std::uint32_t ttl = 3;                 // seconds; > 0 = Ack, 0 = Nack (entry type 0x07).
    std::uint8_t counter = 0;              // 4-bit counter, echoes the Subscribe (TR_SOMEIP §7.1.3).
    // 12-bit Reserved field of the entry (bytes 12-13, sharing the 16-bit word
    // with the 4-bit counter) — same override semantics as
    // `SubscribeEventgroupTarget::entry_reserved`; default unset → spec-canonical 0.
    std::optional<std::uint16_t> entry_reserved;
    // Multicast delivery endpoint advertised in the Ack's option (TR_SOMEIP
    // §7.4.3): the group:port the client joins for multicast event delivery.
    // Set → the Ack references one option (run 1, a 56-byte Ack); unset (the
    // default) → unicast events, no options referenced (a 44-byte Ack).
    std::optional<Ipv4Endpoint> multicast_endpoint;
    // Option type for `multicast_endpoint` (TR_SOMEIP §7.4.3): 0x14 = IPv4
    // Multicast Option, the canonical type for an Ack's event-delivery group.
    // Overridable for a case that drives an unknown/alternate option type.
    std::uint8_t multicast_option_type = 0x14;
};

// Full parameters for one SubscribeEventgroupAck datagram — identity plus the
// server-side emit state. Used by the low-level `buildSubscribeEventgroupAck`.
struct SubscribeEventgroupAckParams {
    SubscribeEventgroupAckTarget target{};
    std::uint16_t session_id = 0x0001;     // server SD session counter.
    std::uint8_t sd_flags = ::tc8::sd_flags::kRebootUnicast;  // same cadence as Offer.
};

// Builds the SOME/IP-SD SubscribeEventgroupAck/Nack datagram (entry type 0x07):
// 44 bytes when `target.multicast_endpoint` is unset (no options, SOME/IP
// Length 36), 56 bytes when set (one referenced IPv4 Multicast option, Length
// 48) — the Ack/Offer parallel of `buildOfferService` vs
// `buildOfferServiceWithEndpoint`. TTL == 0 makes it a Nack. Caller owns the
// UDP/IP/Ethernet encapsulation (`emitSubscribeEventgroupAck`).
std::vector<std::uint8_t> buildSubscribeEventgroupAck(const SubscribeEventgroupAckParams &p);

// Tester server-role SubscribeEventgroupAck/Nack EMIT. Sends the answer from the
// tester's SD port (30490 — the server's SD endpoint) to the DUT client's SD
// endpoint `client_sd_dest`. That endpoint is the SOURCE of the captured
// Subscribe (this frame's src_ip) and is runtime-derived, so it has NO default —
// the caller must pass it (mirroring `MethodEndpoint`'s deliberate no-default
// rule), preventing a silent fall-back to a hardcoded address. Source port = SD
// port so the DUT accepts it as a valid SD message, exactly as `sendSdUnicast`.
// Returns 0 on success or the negative `sendUdpUnicast` sentinel.
int emitSubscribeEventgroupAck(std::string_view iface, const SubscribeEventgroupAckParams &p,
                               const SubscribeDestination &client_sd_dest);

// SubscribeEventgroupNack — the TTL == 0 form of the same entry type 0x07. There
// is no separate Nack entry type in SOME/IP-SD; this forces `target.ttl = 0` and
// delegates to the Ack builder (one wire SSOT), the force-and-delegate idiom of
// `buildMethodError` over `buildMethodRequest`. There is intentionally no
// `emitSubscribeEventgroupNack`: the emit asymmetry mirrors the RPC family, where
// `emitMethodReply` serves Response and Error alike — to emit a Nack, pass the
// caller's params with `target.ttl == 0` to `emitSubscribeEventgroupAck` (or emit
// this builder's bytes). The caller's `target.ttl` is overwritten to 0; every
// other field (Service/Instance/Eventgroup/Counter/Session/Reboot) is echoed.
std::vector<std::uint8_t> buildSubscribeEventgroupNack(SubscribeEventgroupAckParams p);

}  // namespace tc8::stimulus
