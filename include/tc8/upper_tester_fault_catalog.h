#pragma once

// Upper Tester FAULT-FLAVOUR catalogues — the egress, ingress, application and ETS
// flavour bytes a `_NEG` case arms over the UT channel, and the lwIP fixture's hooks
// route on. Split out of `tc8/upper_tester_protocol.h` on 2026-09-25 because the two
// change at rates an order of magnitude apart: the opcode and wire contract there is
// stable, while these catalogues grow every time a negative case needs a new mechanism,
// and a header carrying both makes every flavour a whole-suite recompile
// (docs/tech-debt.md TD-44, which has the measurement).
//
// The SSOT property is unchanged and is why this is a header at all rather than two
// private enums: one catalogue is written here and read by BOTH the harness that arms a
// flavour and the DUT fixture that acts on it, so a value cannot drift between the two
// ends of the wire.
//
// ⚠ Include this DIRECTLY wherever a flavour constant is named. It is deliberately NOT
// included by `upper_tester_protocol.h`: a transitive include would put every consumer
// of the opcode contract back in the blast radius and undo the split silently, with
// nothing failing to say so. `sce_integration/cases/_fault_flavor_arm.h` includes it, so
// a case that arms through those helpers already has it.
//
// ⚠ Values are WIRE values. Appending is safe; renumbering is not — a DUT built from an
// older tree would route the new number to the old behaviour, which reads as an inert
// fault rather than an error.

#include <cstdint>

namespace tc8::ut {

// `OpSetEgressFlavor` field-fault catalog (lwIP fixture egress hook). Distinct from
// the §4.5 link-local autoconf kFlavor* above (OpStartLLAutoconfBuggy). The DUT
// emits a frame legitimately and the netif link-output hook rewrites ONE header
// field on the way out (NOT recomputing the checksum — each guard reads the mutated
// field, and libpcap delivers the checksum-stale frame regardless), routed by the
// lwIP fixture glue, never by lwIP itself. One contiguous catalog across protocols;
// the flavor name carries the protocol+field. A field shared by a request-shape and a
// reply-shape case (htype, hlen) uses ONE flavor — the offset is identical and the
// case's provocation selects which frame. TCP being stateful, its flavors are
// segment-selective (gated on the segment the case observes) so the fault never
// breaks the handshake the observed segment depends on.
inline constexpr std::uint8_t kEgressFaultNone        = 0x00;
// ARP-over-Ethernet (no checksum):
inline constexpr std::uint8_t kArpFaultOpcodeWrong     = 0x01;  // RFC 826 opcode: ARP_07/ARP_12 (request MUST be 1)
inline constexpr std::uint8_t kArpFaultHwTypeWrong     = 0x02;  // RFC 826 htype:  ARP_08/ARP_46 (MUST be 1, Ethernet)
inline constexpr std::uint8_t kArpFaultProtoTypeWrong  = 0x03;  // RFC 826 ptype:  ARP_09 (MUST be 0x0800, IPv4)
inline constexpr std::uint8_t kArpFaultHwLenWrong      = 0x04;  // RFC 826 hlen:   ARP_10/ARP_47 (MUST be 6)
inline constexpr std::uint8_t kArpFaultProtoLenWrong   = 0x05;  // RFC 826 plen:   ARP_11 (MUST be 4)
// IPv4/UDP (the egress hook rewrites the named field; the resulting checksum
// mismatch is immaterial — each guard reads the field, and the checksum flavor
// invalidates the checksum field directly):
inline constexpr std::uint8_t kUdpFaultSrcPortWrong    = 0x06;  // RFC 768 src port:  §4.6.5.4 UDP_FIELDS_01
inline constexpr std::uint8_t kUdpFaultDstPortWrong    = 0x07;  // RFC 768 dst port:  §4.6.5.4 UDP_FIELDS_02
inline constexpr std::uint8_t kUdpFaultLengthWrong     = 0x08;  // RFC 768 length:    §4.6.5.4 UDP_FIELDS_06/07 + §4.6.5.3 UDP_Padding_02
inline constexpr std::uint8_t kUdpFaultChecksumWrong   = 0x09;  // RFC 768 checksum:  §4.6.5.4 UDP_FIELDS_13/14
// TCP (segment-selective; the flavor names the field + the segment it targets):
inline constexpr std::uint8_t kTcpFaultSynAckAckWrong   = 0x0A;  // RFC 793 ack num:  §4.8 TCP_SEQUENCE_01/03/04 (passive-open SYN,ACK acks tester ISN+1)
inline constexpr std::uint8_t kTcpFaultDataChecksumWrong = 0x0B; // RFC 793 checksum: §4.8 TCP_CHECKSUM_03 (data segment) + §4.8 TCP_HEADER_01 (data segment header validity)
inline constexpr std::uint8_t kTcpFaultRstSeqWrong      = 0x0C;  // RFC 793 §3.9 seq:  §4.8 TCP_BASICS_04/05 + FLAGS_INVALID_02 (RST SEQ off the spec value)
inline constexpr std::uint8_t kTcpFaultSynMssZero       = 0x0D;  // RFC 1122 §4.2.2.6 MSS option: §4.8 TCP_MSS_OPTIONS_11 (active-OPEN SYN advertises a receive MSS)
inline constexpr std::uint8_t kTcpFaultSynMssDefault    = 0x0E;  // RFC 1122 §4.2.2.6 MSS value:  §4.8 TCP_MSS_OPTIONS_12 (advertised MSS differs from the 536 default)
// ICMPv4 (§4.3) + IPv4 header (§4.4) on a DUT ICMP message, gated per ICMP type so only
// the observed frame is touched: the Echo Reply (type 0) for echo id/seq + IPv4 ttl /
// header checksum (0x0F-0x12); the Destination Unreachable (type 3) for code (0x13):
inline constexpr std::uint8_t kIcmpFaultEchoIdWrong    = 0x0F;  // RFC 792 echo id:  §4.3 ICMPv4_TYPE_09 (reply echoes the request identifier); also §4.4.4.7 REASSEMBLY_11/_13 on the reassembled reply
inline constexpr std::uint8_t kIcmpFaultEchoSeqWrong   = 0x10;  // RFC 792 echo seq: §4.3 ICMPv4_TYPE_09 (reply echoes the request sequence); also §4.4.4.7 REASSEMBLY_11/_13 on the reassembled reply
inline constexpr std::uint8_t kIpv4FaultTtlZero        = 0x11;  // RFC 1122 §3.2.1.7 TTL:  §4.4 IPv4_TTL_01 (emitted TTL MUST be non-zero)
inline constexpr std::uint8_t kIpv4FaultHdrChecksumWrong = 0x12; // RFC 791 §3.1 header checksum: §4.4 IPv4_CHECKSUM_05
inline constexpr std::uint8_t kIcmpFaultDestUnreachCodeWrong = 0x13; // RFC 1122 §3.2.2.1 code: §4.3 ICMPv4_TYPE_18 (Protocol Unreachable code 2)
// TCP (§4.8) pure-ACK ack_num. Appended at the catalog tail (the value space is
// append-only; numeric grouping with the 0x0A-0x0E TCP block is not maintained for
// later additions). Gated on a pure DUT ACK — the flavor names the field, the caller's
// arm timing names which ACK: per-phase after the handshake for a data-elicited ACK
// (HEADER_02/05/06, ACKNOWLEDGEMENT_02/03), or armed up front for the single ACK of a
// SYN-SENT open (SEQUENCE_02). The handshake third leg (also a pure ACK) is escaped by
// the arm timing, not the gate.
inline constexpr std::uint8_t kTcpFaultPureAckNumWrong = 0x14;  // RFC 793 §3.9 ack num: §4.8 HEADER_02/05/06 + ACKNOWLEDGEMENT_02/03 + SEQUENCE_02
// IPv4 header (§4.4) on a DUT Echo Reply, gated on type 0 like the ttl/checksum flavors.
// libtins validates only IHL on parse (not version or total_length), so a mutated
// version nibble / sub-minimum total_length is dissected and the guard reads the field.
inline constexpr std::uint8_t kIpv4FaultTotalLenWrong = 0x15;  // RFC 791 §3.1 total length: §4.4 IPv4_HEADER_01 (sub-20 minimum)
inline constexpr std::uint8_t kIpv4FaultVersionWrong  = 0x16;  // RFC 791 §3.1 version:      §4.4 IPv4_VERSION_03 (version nibble != 4)
// Corrupt the first byte of a DUT Echo Reply's Data region (payload length unchanged) so
// the echoed bytes no longer match the index pattern — the "wrong bytes" half of the
// 576-octet echo guard, distinct from the truncation half.
inline constexpr std::uint8_t kIcmpFaultEchoPayloadByteWrong = 0x17;  // RFC 792 echo data: §4.4 IPv4_HEADER_05 (548 B Data echoed verbatim — wrong-bytes half); also §4.4.4.7 REASSEMBLY_11/_13 (reassembled data)
// Shrink the Echo Reply's IP total_length so the dissected payload carries fewer than the 548
// echoed Data bytes (libtins slices the inner PDU by total_length) — the truncation half of
// the same 576-octet echo guard, distinct from the wrong-bytes half above.
inline constexpr std::uint8_t kIcmpFaultEchoPayloadTruncate = 0x18;  // RFC 791 §3.1 total length: §4.4 IPv4_HEADER_05 (data truncated)
// Shrink a DUT TCP DATA segment's IP total_length so libtins re-slices the dissected payload
// below the spec segment size (the same total_length-truncation as the ICMP echo truncate above,
// gated on a TCP segment carrying payload) — the guard reads payload_len, which drops off the
// expected MSS.
inline constexpr std::uint8_t kTcpFaultDataSegTruncate = 0x19;  // RFC 1122 §4.2.2.6 segment size: §4.8 MSS_OPTIONS_06/09/10 (data segment truncated below the MSS)
// RFC 826 target hardware address in a DUT-emitted ARP RESPONSE — the address the DUT is
// answering TO, which §4.2.4.2 ARP_45 requires to track the sender of the Request being
// answered rather than a first correspondent remembered from an earlier exchange.
//
// ⚠ ARP_45 grades TWO Responses and this flavor corrupts whichever one is in flight, so the
// negative that reaches the SECOND guard arms MID-STREAM (emitEgressFlavorArmMidStream) after
// the first Response has left. Corrupting both would land the first guard and the run would
// never reach the second — the same one-run-one-final constraint the per-final coverage map
// exists for. No occurrence counter is needed in the UT protocol: arming between emissions is
// how the multi-phase TCP ack negatives already select a later frame.
inline constexpr std::uint8_t kArpFaultResponseTargetHwWrong = 0x1A;  // RFC 826 target hw: §4.2.4.2 ARP_45 (a Response answers the Request's sender)
// The Ethernet destination of a DUT-emitted UDP datagram — the field §4.2.4.2 ARP_49 reads to
// decide whether the DUT still addressed its egress to the MAC it was taught.
//
// ⚠ Scoped to DUT UDP egress, and unlike the narrowings above that is a REQUIREMENT rather
// than a convenience. Every other flavor in this catalog is self-filtering by the field it
// corrupts: an ARP field cannot match a TCP segment, so an armed flavor passes over frames it
// does not describe. A link-layer destination is present on EVERY frame, so an unscoped version
// would corrupt whichever frame left first — including the DUT's own UT acknowledgement, which
// would strand the control channel and make the fault read as inert instead of effective.
inline constexpr std::uint8_t kEthFaultUdpEgressDstWrong = 0x1B;  // §4.2.4.2 ARP_49 (UDP egress carries the learned MAC until the entry expires)
inline constexpr std::uint8_t kEgressFaultMax         = kEthFaultUdpEgressDstWrong;

// `OpSetIngressFlavor` ingress-reaction catalog (lwIP fixture input hook). The
// reception cases where a conformant DUT's reaction to an inbound frame is itself
// the property under test, so there is no DUT egress field to corrupt: the input
// hook makes the buggy DUT exhibit the forbidden reaction the positive case proves
// absent. Four reaction kinds today: prohibited EMISSION (§4.2.4.2 ARP — the DUT
// must drop a malformed/foreign frame silently, the fault makes it reply/learn;
// §4.3 ICMPv4 — the DUT must stay silent for an Info Request / unknown type /
// bad-checksum Echo / broadcast or fragmented error trigger, the fault synthesizes
// the prohibited ICMP reply; §4.8 TCP — the DUT must silently drop an unacceptable
// segment, the fault synthesizes the prohibited TCP response, e.g. a RST after a
// pure ACK), prohibited ACCEPTANCE (§4.6.5.4 UDP — the DUT must
// discard a malformed datagram, the fault makes it accept and deliver it to the
// receive-counting app), and prohibited REJECTION (§4.6.5.4 UDP — the DUT must
// accept a valid edge-case datagram, the fault makes it drop one it must deliver).
// The ARP and ICMP emission faults synthesize a frame back to the inbound sender
// (the conformant DUT emits nothing, so there is no egress to corrupt — the netif
// input hook builds the forbidden frame itself); the UDP faults mutate or swallow
// the inbound datagram in place. One contiguous catalog; the flavor name carries
// the protocol + reaction.
inline constexpr std::uint8_t kIngressFaultNone          = 0x00;
// ARP-over-Ethernet prohibited emission:
inline constexpr std::uint8_t kArpFaultReplyToDropFrame  = 0x01;  // §4.2.4.2 reply-absence: ARP_21/27/37/42 (reply to a frame the DUT must drop)
inline constexpr std::uint8_t kArpFaultLearnFromDropFrame = 0x02;  // §4.2.4.2 drop-and-emit: ARP_22/28/38 (learn the dropped Response's address)
// UDP prohibited acceptance — the input hook zeroes the inbound datagram's UDP
// checksum field so lwIP's `chksum != 0` guard skips validation and delivers it. On
// lwIP this is the ONLY drop gate for these cases: the length-field mutants
// (FIELDS_09 length 0, _10 length > payload, DATAGRAMLENGTH_01 length < payload)
// break the checksum because the length field is checksum-covered, and FIELDS_15
// corrupts the checksum directly — so one "skip checksum validation" fault makes them
// all accepted. (FIELDS_08's sub-8-byte truncation drops earlier, at the UDP
// minimum-length gate, and is not faithfully faultable this way — see
// dut/lwip_dut/README.md.)
inline constexpr std::uint8_t kUdpFaultAcceptBadChecksum  = 0x03;  // §4.6.5.4 acceptance: UDP_FIELDS_09/10/15 + DATAGRAMLENGTH_01 (accept a datagram its checksum check must drop)
// UDP prohibited rejection — the input hook swallows the inbound data-listener UDP
// frame (never forwards it to lwIP) so the receive-counting app never sees a datagram
// the DUT must accept. Models a DUT that wrongly drops a valid edge-case datagram.
inline constexpr std::uint8_t kUdpFaultRejectValid       = 0x04;  // §4.6.5.4 rejection: UDP_FIELDS_03 (src port 0) / _16 (checksum 0) (drop a datagram it must accept)
// ICMPv4 prohibited emission (§4.3) — the input hook synthesizes the ICMP reply a
// conformant DUT must NOT send for the inbound trigger, addressed back to the
// trigger's sender with the DUT's own source identity (the DUT emits nothing, so
// there is no egress field to corrupt). The flavor names the reply type; the case's
// trigger frame selects which prohibited reply is in scope:
inline constexpr std::uint8_t kIcmpFaultSynthEchoReply    = 0x05;  // §4.3.3.2 TYPE_10 (bad-checksum Echo) / §4.3.3.1 ERROR_05 (unknown type): synthesize an Echo Reply (type 0)
inline constexpr std::uint8_t kIcmpFaultSynthInfoReply    = 0x06;  // §4.3.3.2 TYPE_16: synthesize an Information Reply (type 16, RFC 1122 §3.2.2.7 SHOULD NOT)
inline constexpr std::uint8_t kIcmpFaultSynthParamProblem = 0x07;  // §4.3.3.1 ERROR_03 (fragmented) / ERROR_04 (broadcast): synthesize a Parameter Problem (type 12)
// TCP behavioral prohibited emission (§4.8) — the input hook synthesizes a forbidden TCP
// response on the connection's 4-tuple (swapped from the inbound trigger; the synthesized
// source IP is the DUT's own netif address, so a multicast-destination trigger still yields
// a DUT-sourced reply). RFC 793 §3.9 guards check only the 4-tuple + flag, never seq/ack, so
// the synthesized segment needs no connection-state tracking. The flavor names the response;
// its dispatch gate names the trigger:
inline constexpr std::uint8_t kTcpSynthRst               = 0x08;  // §4.8.6.18 ACKNOWLEDGEMENT_04 + §4.8.6.7 FLAGS_PROCESSING_11 (duplicate ACK in EST, itself a pure ACK): synthesize a RST on a pure ACK (RFC 793 §3.9 MUST NOT)
inline constexpr std::uint8_t kTcpSynthAck               = 0x09;  // synthesize a challenge ACK on a SYN/PSH segment the DUT must drop (RFC 1122 §4.2.3.10 / RFC 793 §3.1; e.g. §4.8.6.16 HEADER_07/08/09/11, CHECKSUM_02 — not exhaustive, grep the kTcpSynthAck arm for the full set)
// §4.8 TCP must-not-respond family — synthesize a RST when the DUT receives a
// "disruptive" segment (one carrying RST, FIN, URG, or PSH) that RFC 793 §3.9
// requires it to process or drop WITHOUT emitting a response. The gate is the
// disruptive-flag union: it EXCLUDES a bare pure ACK and a bare SYN, so the
// handshake (SYN, SYN|ACK, third-leg ACK) and the tester's later auto-ACKs (e.g.
// closing_08's FW1->FW2 FIN-ACK) never trip it — only the case's deliberate
// trigger does. A synthesized RST trips every guard in this family (each fails on
// is_dut_rst, or on "any DUT segment" which a RST satisfies):
inline constexpr std::uint8_t kTcpSynthRstOnDisruptive   = 0x0A;  // §4.8 must-not-respond family: synthesize the prohibited RST (e.g. FLAGS_INVALID_01/03/04/15, FLAGS_PROCESSING_07/08, CLOSING_03/07/08/09/13, UNACCEPTABLE_02 — not exhaustive, grep the kTcpSynthRstOnDisruptive arm)
// Extends the §4.3 ICMP synth family above; numbered 0x0B (after the TCP synths)
// to avoid renumbering 0x05-0x0A — the dispatch keys on the value, not its order.
inline constexpr std::uint8_t kIcmpFaultSynthTimeExceeded = 0x0B;  // §4.3.3.2 TYPE_04 (incomplete reassembly, fragment zero never arrives): synthesize a Time Exceeded (type 11)
inline constexpr std::uint8_t kTcpSynthFinOnDisruptive   = 0x0C;  // §4.8.6.4 CALL_RECEIVE_05 (FIN in CLOSE-WAIT before app close): synthesize the prohibited FIN+ACK (RFC 793 §3.5 MUST NOT)
// §4.8 TCP must-MOVE-to-CLOSED — a DROP seam (not a synthesis): swallow the inbound
// RST-bearing segment at the netif input so lwIP's TCP never sees it, modelling a DUT
// that fails to honour the reset. The kUdpFaultRejectValid sibling (pbuf_free; never
// forwarded), not a tcp_in.c patch. Unlike the synth family above, the violation here is
// the ABSENCE of the required CLOSED transition — observed as the DUT continuing to
// retransmit its SYN (lwIP's fixed 1 s SYN cadence) instead of going quiet:
inline constexpr std::uint8_t kTcpDropDisruptiveRst      = 0x0D;  // §4.8.6.6 FLAGS_INVALID_05 (SYN-SENT must move to CLOSED on RST+acceptable-ACK): drop the RST so the DUT stays open and keeps retransmitting its SYN
// §4.8.6.16 TCP source-port demultiplexing — a SYNTHESIS keyed on connection state.
// The conformant DUT demultiplexes by the full 4-tuple (RFC 793 §3.1 / §3.9), so an
// in-window data segment whose SOURCE port differs from the established peer's matches
// no connection and is dropped silently. A source-port-blind DUT would match it to the
// connection by local (destination) port alone and ACK it. The hook models that bug:
// it walks tcp_active_pcbs for the ESTABLISHED connection on the segment's destination
// port whose remote port differs from the segment's source port, then synthesizes the
// prohibited pure ACK on that connection's real 4-tuple. The wrong source port is not the
// connection's remote port, so the pcb walk is the only way to recover the real one —
// the kTcpSynth* swap would reply to the wrong port, missing the EST-4-tuple guard:
inline constexpr std::uint8_t kTcpSynthAckSrcPortBlind   = 0x0E;  // §4.8.6.16 HEADER_04 (must drop a segment from the wrong source port): synthesize the prohibited pure ACK on the EST 4-tuple recovered from the active-pcb walk
// §4.4.4.7 IPv4 reassembly — a DROP seam, the kTcpDropDisruptiveRst sibling: swallow
// the inbound LAST fragment of a datagram (MF clear, fragment offset non-zero) at the
// netif input, so lwIP's reassembly never completes the bucket. Models a DUT that loses
// a fragment it received and must keep: the bucket expires and the DUT reports the
// discard with an ICMP Time Exceeded code 1 quoting the head fragment (RFC 792), through
// its own reporting path. An unfragmented frame (offset 0, MF clear) — the UT control
// channel included — and every earlier fragment pass untouched:
inline constexpr std::uint8_t kIpv4FaultDropLastFragment = 0x0F;  // §4.4.4.7 REASSEMBLY_11 (timer) / _13 (overlap): the DUT discards the datagram and reports the expiry
// §4.2 ARP cache staleness — a DROP seam at the netif input, the sibling of
// kArpFaultLearnFromDropFrame above. That one makes the DUT learn an address it must
// NOT learn; this one makes it fail to learn one it MUST, which is the violation the
// cache-populated guards forbid: with the teaching swallowed the table never holds the
// address, so the DUT resolves by emitting its own Request.
//
// ARP REQUEST ONLY, and that is not a narrowing for tidiness: the lwIP DUT resolves the
// tester for its own UT control-plane ACKs and the tester answers with a RESPONSE, so
// swallowing responses would starve the control channel — the case would report nothing
// and an effective fault would read as inert. A gratuitous-Response teaching (ARP_06) is
// therefore out of this flavor's reach and needs its own.
inline constexpr std::uint8_t kArpFaultIgnoreLearn       = 0x10;  // §4.2.4.1 cache-populated absence: ARP_04 (the DUT must not emit a Request for an address it was taught)
// §4.4.4.6 IPv4 reassembly tuple — a MUTATE seam, unlike the drop seams above. The
// FRAGMENTS_02/03/04 positives each send a fragment pair differing in exactly one
// reassembly-tuple field (id, source address, protocol) and forbid the DUT to
// reassemble them. Rewriting the later fragment's field to match the head's at the
// netif input makes the STACK see a matching pair it legitimately reassembles, so the
// DUT answers — the violation the positive grades, while the WIRE still carried the
// mismatch the tester injected. Recomputes the IPv4 header checksum, which a drop seam
// never has to: lwIP validates it and would otherwise discard the frame, and the fault
// would read as inert. One flavor covers all three fields because the tuple is what
// matching is defined over; never an ip4_reass.c patch.
inline constexpr std::uint8_t kIpv4FaultNormaliseFragTuple = 0x11;  // §4.4.4.6 FRAGMENTS_02/03/04: the DUT reassembles fragments whose tuple does not match
// §4.2.4.1 cache UPDATE — the narrower sibling of kArpFaultIgnoreLearn. That one swallows
// every teaching Request, leaving the table empty so the DUT resolves; this one swallows
// only a Request re-teaching an address the table ALREADY holds, so the FIRST MAC survives
// and the DUT addresses its egress to the stale one. Two flavours rather than one because
// they fire DIFFERENT finals of the same double-injection case: the absent-entry path gives
// `dut_arp_request_after_double_injection`, the stale-entry path `udp_eth_dst_is_mac1_not_mac2`.
// Request-only for the same control-plane reason as its sibling.
inline constexpr std::uint8_t kArpFaultIgnoreUpdate      = 0x12;  // §4.2.4.1 cache-update: ARP_32 (a second teaching must replace the first)
// ⚠ A resolve-before-send seed does NOT belong in this catalog, whatever value it is given.
// Such a seed would hand the DUT the tester's address so its egress carried no ARP Request in
// front of it — but the arm cannot be its own seed: the hook reads the flavour while the arm
// frame passes, and the UT handler sets it only after delivery; by any later frame the DUT has
// already resolved, because answering the arm is what makes it resolve. See docs/tech-debt.md
// TD-46 before reaching for the idea again. The lesson is the ORDERING, not a reserved byte,
// so no value is held back for it.
// §4.2.4.1 cache UPDATE by a GRATUITOUS Response — the opcode-2 counterpart of
// kArpFaultIgnoreUpdate, and needed because that one is Request-only. TD-32 records what lwIP
// etharp does with a gratuitous Response: it UPDATES an existing entry although it never
// creates one, and ARP_34's pass depends on exactly that update carrying MAC2 over the MAC1 its
// opening Request taught. Swallowing it leaves MAC1 in the table, which is the
// `udp_eth_dst_is_mac1_not_mac2` final.
//
// ⚠ Gated on target_ip == sender_ip, and that IS the control-plane safety argument rather than
// a shape convenience: the sibling flavors above take Requests only because swallowing every
// Response would eat the tester's answer to the DUT's own resolution and starve the UT channel.
// A tester answering a Request addresses it to the DUT, so it is never gratuitous — this gate
// admits only frames no control plane depends on.
inline constexpr std::uint8_t kArpFaultIgnoreGratuitous  = 0x13;  // §4.2.4.1 cache-update: ARP_34 (a gratuitous re-teaching must replace the first)
// §4.3.3.2 ICMP Timestamp synthesis. lwIP does not implement Timestamp at all (icmp.c counts
// ICMP_TS and drops), so ICMPv4_TYPE_12 is a platform_known_fail here and no run can corrupt a
// reply the stack never emits — the frame has to be synthesized, as the Echo / Information /
// Parameter Problem synth flavors above already do for their own absent reactions. Echoes the
// request's identifier and deliberately NOT its sequence, so the reply lands the case's
// sequence guard rather than its identifier guard (the identifier half is already disposed by
// a negative row, and one run reaches one final).
inline constexpr std::uint8_t kIcmpFaultSynthTimestampReplyBadSeq = 0x14;  // §4.3.3.2 TYPE_12: a Timestamp Reply that does not echo the sequence
// §4.4.4.7 reassembly-window escape — a DEFER seam, unlike every drop and mutate flavor above.
// The hook keeps a copy of a head fragment (MF set, offset 0) and swallows it, then replays the
// copy immediately ahead of the matching tail, so the stack meets the pair back-to-back however
// long the wire gap between them was. That is precisely what a DUT whose reassembly timer is
// too long looks like from the tester: the pair completes and a correct Echo Reply arrives,
// which is the emission IPv4_REASSEMBLY_10's phase B forbids once its bucket has expired.
//
// ⚠ The obvious shortcut — clear MF on the head so the stack takes it for a whole datagram —
// was MEASURED INERT on 2026-09-25 and is not a timing bug: the head carries the ICMP checksum
// of the WHOLE message, so a truncated datagram fails CHECKSUM_CHECK_ICMP in icmp_input and is
// dropped in silence. Recomputing that checksum would not rescue it either, because a stack
// that genuinely mishandles MF would hand icmp_input the same stale checksum and drop it too —
// the shortcut cannot produce this guard's observable on ANY stack, which is why the seam
// defers a frame instead of rewriting one.
//
// ⚠ Must be armed MID-STREAM (emitIngressFlavorArmMidStream), between the phases. Armed from
// the start it would defer phase A's head the same way, the positive's phase-A guard would take
// the run, and phase B — the half under test — would never be entered.
inline constexpr std::uint8_t kIpv4FaultHoldFirstFragment = 0x15;  // §4.4.4.7 REASSEMBLY_10: the DUT answers a pair the wire spread across its reassembly window
inline constexpr std::uint8_t kIngressFaultMax           = kIpv4FaultHoldFirstFragment;

// `OpSetAppFlavor` (0x1A) APP-LAYER reception-fault flavor byte. Distinct from the
// egress/ingress catalogs: those mutate or synthesize wire frames at the netif hook,
// whereas these fault the shared data listener (UpperTesterServer::dataListenerLoop /
// createUdpReceivePorts) — the application running on the DUT stack, below the netif
// glue's reach. Two reaction kinds: a DISCARD skip (the listener keeps a datagram RFC
// 1122 places a destination-address discard on) and a REPORT corruption (the §4.6.5.5
// UDP User-Interface Confirmation surfaces a wrong src port / src IP / payload / receive-
// port count for a correctly-received datagram — modelling a DUT whose receive operation
// returns wrong metadata, the only faithful site since the stack delivered it correctly).
// One contiguous catalog; the flavor name carries the policy or report field it faults.
inline constexpr std::uint8_t kAppFaultNone                   = 0x00;
// §4.4.4.5 ADDRESSING_02: the listener silently discards a datagram whose destination
// is the interface directed broadcast (limited broadcast 255.255.255.255 is kept).
// This flavor skips that discard so the DUT counts the directed broadcast it must
// drop (ipv4_addressing_02_neg). lwIP delivers directed broadcast to the INADDR_ANY
// data socket (IP_SOF_BROADCAST_RECV off), so the drop is genuinely the listener's.
inline constexpr std::uint8_t kAppFaultAcceptDirectedBroadcast = 0x01;
// §4.6.5.6 UDP_INTRODUCTION_02: the listener silently denies a datagram whose
// destination is the all-systems multicast 224.0.0.1 (the TC8 security profile inverts
// the RFC 1122 §4.1.1 SHOULD-allow). lwIP delivers it to the socket (ip4_input accepts
// every multicast destination with LWIP_IGMP off), so the deny is the listener's; this
// flavor skips it so the DUT counts the multicast it must drop (udp_introduction_02_neg).
inline constexpr std::uint8_t kAppFaultAcceptMulticast        = 0x02;
// §4.6.5.5 UDP User-Interface + §4.6.5.4 FIELDS Confirmation report corruption — the
// listener received the datagram correctly but reports a wrong field, so the positive's
// field guard goes from pass to fail. Each names the GetReceivedUdp / CreateUdpReceivePorts
// field it mangles; the conformant path (None) reports correctly (the _neg's fault-inert
// branch):
inline constexpr std::uint8_t kAppFaultReportWrongSrcPort     = 0x03;  // §4.6.5.5 UI_03: GetReceivedUdp src port (RFC 768 receive returns source port)
inline constexpr std::uint8_t kAppFaultReportWrongSrcIp       = 0x04;  // §4.6.5.5 UI_04: GetReceivedUdp src IP (RFC 768 receive returns source IP)
inline constexpr std::uint8_t kAppFaultReportWrongPayload     = 0x05;  // §4.6.5.5 UI_02: GetReceivedUdp payload bytes (RFC 768 receive returns data octets)
inline constexpr std::uint8_t kAppFaultMiscountPorts          = 0x06;  // §4.6.5.5 UI_01: CreateUdpReceivePorts actual_count (RFC 768 create N receive ports)
inline constexpr std::uint8_t kAppFaultReportWrongLength      = 0x07;  // §4.6.5.4 UDP_FIELDS_12: GetReceivedUdp payload length (RFC 768 receive returns datagram length)
// The receipt report itself rather than one of its fields: the listener received the
// datagram but its receive operation never surfaces it, so GetReceivedUdp answers
// received=0. One flavor serves every positive that asserts a required receipt (UI_02/03/04,
// FIELDS_12) -- the defect is the same whichever field the positive then checks.
inline constexpr std::uint8_t kAppFaultReportNoReceipt        = 0x08;  // §4.6.5.5 / §4.6.5.4: GetReceivedUdp received flag (RFC 768 receive returns the datagram)
inline constexpr std::uint8_t kAppFaultMax                    = kAppFaultReportNoReceipt;

// `OpSetEtsFlavor` (0x1B) SOME/IP application-layer fault flavor byte. The harness-owned
// EtsImpl (the EnhancedTestability service methods) reads it: a non-None flavor makes an
// EtsImpl method misbehave so a §5.1.6 SOMEIP_ETS get/set/reset guard (which asserts the
// post-set or post-reset readback) goes from pass to fail. The only faithful SOME/IP fault
// site — the response serialization is vendored-vsomeip-owned, but the field value the getter
// returns and the reset side-effect are EtsImpl-owned. The conformant path (None) behaves
// correctly (the _neg's fault-inert branch). tc8-dut-only.
inline constexpr std::uint8_t kEtsFaultNone                   = 0x00;
inline constexpr std::uint8_t kEtsFaultFieldValueWrong        = 0x01;  // §5.1.6 SOMEIP_ETS_166/167/168 + 103/104/105: any field or last-value getter (0x40/0x2A/0x28/0x3B/0x3C/0x3D) returns value ^ 0xFF per byte (!= the cached/set value)
inline constexpr std::uint8_t kEtsFaultResetSkip              = 0x02;  // §5.1.6 SOMEIP_ETS_146: resetInterface is a no-op, so the post-reset getFieldA still returns the pre-reset value
inline constexpr std::uint8_t kEtsFaultSetterEchoWrong        = 0x03;  // SOMEIPSRV_RPC_11: the field setter (0x42) response echoes value ^ 0xFF; the store is left correct, and this is distinct from the getter fault so the get/set/get _neg cases keep a correct setter echo
inline constexpr std::uint8_t kEtsFaultEchoArrayWrong        = 0x04;  // §5.1.6 SOMEIP_ETS_067: echoUINT8Array (0x09) appends a byte so the echoed array is non-empty for a zero-length-array request
inline constexpr std::uint8_t kEtsFaultMax                    = kEtsFaultEchoArrayWrong;

}  // namespace tc8::ut
