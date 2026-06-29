#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

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

    // Reboot=1 Unicast=1 (0xC0) until Session ID wraps 0xFFFF -> 0x0000
    // per SD §4.2.1; drops to Unicast-only (0x40) only after the wrap.
    std::uint8_t sd_flags = 0xC0;

    // SD header 24-bit Reserved field (the 3 bytes after the Flags byte).
    // Canonically 0; a case sets non-zero bits to verify the DUT ignores
    // undefined Reserved bits in a FindService SD header per the SOME/IP-SD
    // reserved-handling requirement (PRS_SOMEIPSD_00307). Only the low 24
    // bits are emitted (putBe24).
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

// §5.1.6 SOMEIP_ETS_118 helper: 56-byte FindService variant carrying one
// IPv4 Endpoint option in its Options Array. The entry's #Opt1/#Opt2 stay
// 0 — the option is physically present but UNREFERENCED — so the DUT must
// ignore it per PRS_SOMEIPSD_00268 / SIP_SD_877 / SIP_SD_878 and still
// respond with at least one OfferService.
std::vector<std::uint8_t> buildFindServiceWithOption(const FindServiceParams &p,
                                                     const Ipv4Endpoint &endpoint);

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
    std::uint16_t session_id = 0x0001;
    std::uint8_t sd_flags = 0xC0;  // Reboot=1 Unicast=1 (same cadence as FindService)
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
    // §5.1.6 SOMEIP_ETS_117 / _175 helper: extra options appended after
    // the canonical IPv4 Endpoint option. Each `ExtraSdOption` is encoded
    // as 4 + body.size() bytes (Length 2B BE + Type 1B + Reserved 1B + body)
    // and contributes to the Options Array. OptionsLen and SOME/IP Length
    // auto-extend by the total bytes unless `options_len_override` /
    // `length_override` are explicitly set. Used by:
    //   - _117 (two options of the same IPv4 Endpoint type)
    //   - _175 (one extra Configuration Option, Type 0x01, unreferenced)
    struct ExtraSdOption {
        std::uint8_t type;
        std::vector<std::uint8_t> body;  // body bytes after type+reserved
        std::uint8_t reserved = 0;
    };
    std::vector<ExtraSdOption> extra_options;
};

// Builds the 56-byte SOME/IP-SD SubscribeEventgroup datagram payload
// (16-byte SOME/IP header + 40-byte SD payload: 4B flags/reserved +
// 4B EntriesLen + 16B Type 2 entry + 4B OptionsLen + 12B IPv4 Endpoint
// option). Unlike `buildFindService` (no options), subscribe references
// exactly one option — the tester's UDP endpoint where the DUT Ack/Nack
// is to be sent. Caller is responsible for UDP/IP/Ethernet encapsulation.
std::vector<std::uint8_t> buildSubscribeEventgroup(const SubscribeEventgroupParams &p);

// Destination of a SubscribeEventgroup datagram — the DUT's SD unicast
// endpoint (SD §4.2: Subscribe is sent unicast to the server's SD
// address, not multicast). Default matches the tc8-dut bundled in this
// repo (172.16.0.2 : 30490); real DUTs override via the emitter param.
struct SubscribeDestination {
    // IPv4 in network byte order. 172.16.0.2 → 0xAC 0x10 0x00 0x02 →
    // stored as 0x020010AC on little-endian Linux (byte-order semantics
    // match `Ipv4Endpoint::ipv4_be`).
    std::uint32_t ipv4_be = 0x020010AC;
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
                                std::uint8_t sd_flags = 0xC0,
                                std::uint8_t l4proto = 0x11,
                                const SubscribeDestination &dest = {});

// §5.1.6 SOMEIP_ETS_123/_124/_125 helper: emit one SubscribeEventgroup
// using a caller-controlled SubscribeEventgroupParams (so EntriesLen can
// be corrupted via `entries_len_override`). Same socket lifecycle as
// `emitSubscribeEventgroupOnce` (UDP socket bound to SD port 30490 with
// SO_REUSEADDR); tester endpoint advertised in the option auto-derives
// from the iface IPv4 + SD port unless caller pre-fills `tester_endpoint`.
// Returns 0 on success or a negative errno-derived sentinel on failure.
int emitSubscribeEventgroupRaw(std::string_view iface,
                               SubscribeEventgroupParams params,
                               const SubscribeDestination &dest = {});

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
};

std::vector<std::uint8_t>
buildOfferServiceWithEndpoint(const OfferServiceWithEndpointTarget &t);

int emitOfferServiceMulticastWithEndpoint(std::string_view iface,
                                          const OfferServiceWithEndpointTarget &t,
                                          std::chrono::milliseconds pre_emit_wait =
                                              std::chrono::milliseconds(500));

// §5.1.6 SOMEIP_ETS_088 helper: SD message carrying multiple Type 2
// SubscribeEventgroup entries, all sharing one option run 0
// (single IPv4 Endpoint option). Each entry's eventgroup_id / ttl
// / counter / etc. lives in its own SubscribeEventgroupTarget. The
// DUT walks the entries one at a time and emits Ack/Nack for each
// per SD §4.2 (PRS_SOMEIPSD_00263).
struct MultiSubscribeEventgroupParams {
    std::vector<SubscribeEventgroupTarget> entries;
    Ipv4Endpoint tester_endpoint{};
    std::uint16_t session_id = 0x0001;
    std::uint8_t sd_flags = 0xC0;
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

}  // namespace tc8::stimulus
