#pragma once

#include <cstdint>

#include "tc8/protocol_frames/tcp_frame.h"

#include "test_config.h"

namespace tc8 {

// SCE Named Context carrying fields parsed from an observed RFC 793
// TCP segment. Paired with `tc8::Ipv4Expected` in the SCXML expected
// context — §4.8.6.1 TCP_BASICS only need DUT + tester identity, no
// TCP-specific expectation knobs.
//
// Matching SCXML declaration:
//   <sce:context id="captured" cpp:type="tc8::TcpCaptured"
//                cpp:include="sce_integration/tcp_captured.h"/>
//
// Field choices tracked one-for-one with §4.8.6.1 pass criteria:
//
//   * `flags` — BASICS_01 / 03 gate on individual Control Bits
//     (SYN+ACK, ACK) being set.
//   * `seq_num` — BASICS_04 requires the DUT's RST to carry SEQ=0;
//     BASICS_05 requires SEQ=incoming.ACK (tester chooses the ACK).
//   * `ack_num` — BASICS_01's SYN,ACK acknowledges tester.seq+1.
//     Consumers compare against a stimulus-known value.
//   * `payload_len` — non-Control traffic indicator for BASICS_02/03
//     data-probe variants (not used today; carried for symmetry).
//
// `src_port` / `dst_port` let SCXML guards filter out SOME/IP-over-TCP
// traffic on the same interface (vsomeip port range 30490..30510).
struct TcpCaptured {
    std::uint32_t src_ip         = 0;  // network byte order
    std::uint32_t dst_ip         = 0;  // network byte order
    std::uint16_t src_port       = 0;
    std::uint16_t dst_port       = 0;
    std::uint32_t seq_num        = 0;
    std::uint32_t ack_num        = 0;
    std::uint8_t  data_offset    = 0;  // header length in 32-bit words
    std::uint8_t  flags          = 0;  // CWR ECE URG ACK PSH RST SYN FIN
    std::uint16_t window         = 0;
    std::uint16_t checksum       = 0;
    std::uint16_t urgent_pointer = 0;
    std::uint32_t payload_len    = 0;

    // RFC 793 §3.1 kind=2 MSS option value parsed from the segment, or 0
    // if the segment carried no MSS option. §4.8.6.9 TCP_MSS_OPTIONS_11
    // asserts presence (mss > 0) on the DUT's active-OPEN SYN; _12
    // additionally asserts the value differs from the RFC 1122 §4.2.2.6
    // default (mss != 536). Mirrored from `TcpFrame::mss` at decode time.
    std::uint16_t mss = 0;

    // Stimulus-populated field: the UT OpQueryTcpEstablished reply the
    // tester fetched synchronously before the SCXML listen window
    // opened. BASICS_02's pass guard conjuncts on this to verify the
    // DUT's listener transitioned SYN-RCVD → ESTABLISHED after the
    // 3-way handshake completed.
    //
    //   0xFF = not queried (tristate sentinel; a case that never calls
    //          the UT query leaves it here and guards skip the check),
    //   0x00 = queried, DUT reports not established,
    //   0x01 = queried, DUT reports established.
    //
    // Not filled by `fillTcpCapturedFromFrame` — the stimulus writes
    // directly into the runner's `captured_` via the `Captured& c`
    // argument, before start() initialises the SM and the first
    // dispatch() reads the fields.
    std::uint8_t  ut_established = 0xFF;

    // Stimulus-populated field: the ACK number a spec-conformant DUT
    // is expected to emit in response to the raw-injected data probe.
    // §4.8.6.X TCP_HEADER_02 / _05 / _06 set this to (injected_seq +
    // payload_len) before opening the SCXML listen window, so the
    // SCXML guard can compare `captured.ack_num == captured.expected_
    // ack_num` per RFC 793 §3.9 "ACK with the expected Ack Number"
    // pass criterion. Default 0 is structurally distinct from any
    // plausible kernel-emitted ack_num (which always exceeds the
    // injected ISN by at least 1) so a case that forgets to populate
    // the field never accidentally passes.
    std::uint32_t expected_ack_num = 0U;

    // §4.8.6.10 TCP_OUT_OF_ORDER_03 phase-2 expected ack — separate
    // from `expected_ack_num` because the case observes TWO distinct
    // cumulative ACK values along the same connection: phase-1 after
    // the initial in-order data segment (spec step 3) and phase-2
    // after the gap-filler closes the queued OOO range (spec step 7).
    // A single shared field would let phase-1's guard accidentally
    // satisfy phase-2 (or vice versa) when the SCXML processed events
    // out of expected order. Default 0 is structurally distinct from
    // any plausible kernel-emitted ack_num (always exceeds the
    // injected ISN by at least the first segment's payload length)
    // so a case that forgets to populate the field never accidentally
    // passes.
    std::uint32_t expected_ack_num_phase2 = 0U;

    // §4.8.6.6 TCP_FLAGS_INVALID_08..13 5-phase active-OPEN expected
    // acks — each FLAGS_INVALID case opens a fresh active connection
    // per CASE iter (CASE ∈ {SYN, SYN+ACK, ACK, FIN, data}) on its
    // own port quad. Phase N's challenge ACK from the OTW SEQ probe
    // carries ack_num == DUT.rcv.nxt, which equals the post-handshake
    // tester.snd_nxt for that phase's kernel-chosen ISN_t — distinct
    // per phase, so the existing 2 slots collapse phase 3..5 onto
    // each other. The harness model freezes captured fields before
    // dispatch (TestRunner::kickStimulus runs synchronously before
    // start()), so dispatch cannot reach a state-entry observer
    // pattern; per-phase slots populated during stimulus are the
    // straightforward shape.
    std::uint32_t expected_ack_num_phase3 = 0U;
    std::uint32_t expected_ack_num_phase4 = 0U;
    std::uint32_t expected_ack_num_phase5 = 0U;

    // §4.8.6.11 TCP_RETRANSMISSION_TO_03 stimulus-progress flag.
    // Set by the case's `stimulus()` to true ONLY after
    // `driveActiveOpenEstablished + acceptOne + queryTcpSeqRange`
    // all succeed; remains false on any prelude failure (e.g. the
    // negative IP-flip variant where the tester cannot reach the
    // wrong-IP DUT). The SCXML's first cond gates on this so a
    // negative flow verdicts as `dut_handshake_did_not_complete`
    // instead of the indirect `phase1_tcp_info_query_failed` —
    // semantic accuracy: the handshake never happened, so describing
    // the failure as "TCP_INFO query failed" misattributes the cause.
    bool ut_handshake_completed = false;

    // §4.8.6.11 TCP_RETRANSMISSION_TO_03 kernel-side TCP_INFO
    // snapshots taken at two phase boundaries via the UT
    // OpQueryTcpInfo opcode (0x13). Distinct from pcap-timing-based
    // observation: the tester reads `struct tcp_info` directly off
    // the DUT's connected fd, so RTO doubling and retransmit count
    // are observed in the kernel rather than inferred from inter-
    // frame deltas — eliminating the dependency on pcap delivering
    // retransmits within tight wall-clock windows under
    // `--workers >= 2` parallel load.
    //
    //   * `_p1_*`  snapshot taken AFTER seg1 retx fired (phase-1
    //     verification: tcpi_retransmits >= 1 proves the
    //     RTO timer fired; tcpi_rto reflects the doubled value
    //     RFC 6298 §5 step 5.5 mandates).
    //   * `_p2_*`  snapshot taken AFTER the Karn-excluded ACK
    //     injection + seg2 SEND (phase-2 verification: tcpi_rto
    //     stays at the doubled value — Karn's algorithm preserves
    //     RTO across retx-acknowledging ACKs per RFC 1122 §4.2.3.1
    //     and RFC 6298 §3 / RFC 6298 §5 step 5.3).
    //
    // `_valid` sentinel mirrors the `ut_established == 0xFF` design:
    // false ⇒ stimulus never landed the snapshot (UT round-trip
    // failed, socket closed, etc.) and the SCXML guard chain trips
    // a fail_query verdict before evaluating numeric thresholds.
    bool          ut_tcpi_p1_valid       = false;
    std::uint8_t  ut_tcpi_p1_state       = 0U;
    std::uint32_t ut_tcpi_p1_rto_us      = 0U;
    std::uint8_t  ut_tcpi_p1_retransmits = 0U;
    std::uint32_t ut_tcpi_p1_unacked     = 0U;

    bool          ut_tcpi_p2_valid       = false;
    std::uint8_t  ut_tcpi_p2_state       = 0U;
    std::uint32_t ut_tcpi_p2_rto_us      = 0U;
    std::uint8_t  ut_tcpi_p2_retransmits = 0U;
    std::uint32_t ut_tcpi_p2_unacked     = 0U;

    // §4.8.6.11 TCP_RETRANSMISSION_TO_04 extends the kernel-side
    // observation pattern from two snapshots (Karn's algorithm, _03)
    // to three (exponential backoff across three successive data
    // retransmits). `_p3_*` is taken after the third retx fires
    // (tcpi_retransmits >= 3); the SCXML compares p1/p2/p3 rto_us in
    // strict-growth order to assert RFC 1122 §4.2.3.1 / RFC 6298 §5
    // "more than linear" backoff.
    bool          ut_tcpi_p3_valid       = false;
    std::uint8_t  ut_tcpi_p3_state       = 0U;
    std::uint32_t ut_tcpi_p3_rto_us      = 0U;
    std::uint8_t  ut_tcpi_p3_retransmits = 0U;
    std::uint32_t ut_tcpi_p3_unacked     = 0U;

    // Stimulus-populated field: number of bytes the UT
    // OpReceiveTcpData call returned that ALSO matched the expected
    // payload byte-for-byte. §4.8.6.8 TCP_CLOSING_07/_08 set this to
    // the request length (16) iff the bytes returned by the tc8-dut
    // recv() exactly equal the bytes the tester injected; any
    // mismatch (short / wrong content) leaves this at the 0xFFFFU
    // sentinel so a SCXML guard `ut_received_payload_len == 16U`
    // structurally distinguishes "DUT received proper data" from
    // "didn't receive" / "wrong content". Default-sentinel design
    // mirrors `ut_established`'s 0xFF semantics.
    std::uint16_t ut_received_payload_len = 0xFFFFU;

    // §4.8.6.4 TCP_CALL_RECEIVE_04 phase-specific recv-length fields.
    // The 3-iter compound (EST / FW1 / FW2) needs an independent
    // pass/fail verdict per phase — a single shared field would let
    // a phase 1 success spuriously satisfy phase 2's deadline conjunct
    // when phase 2's actual recv timed out. Mirrors
    // `ut_received_payload_len`'s sentinel-based design (0xFFFFU =
    // not yet matched; payload length on full byte-match).
    std::uint16_t ut_received_payload_len_p1 = 0xFFFFU;
    std::uint16_t ut_received_payload_len_p2 = 0xFFFFU;
    std::uint16_t ut_received_payload_len_p3 = 0xFFFFU;

    // §4.8.6.2 TCP_CHECKSUM_04 stimulus-populated fields. The case
    // drives two consecutive active-OPEN cycles on the same 4-tuple
    // (each aborted by tester-kernel auto-RST against an unbound
    // destination port); stimulus uses two TcpFrameSnippets to capture
    // each cycle's SYN seq directly, then verdicts in SCXML via the
    // evaluate-pattern (mirrors RETRANSMISSION_TO_03's kernel-side
    // observation shape — `dispatch` is a no-op for the case so wire
    // frames buffered during stimulus do not race the SCXML's first
    // tick). `_captured` sentinels distinguish "snippet timed out" from
    // "captured ISN happened to equal 0", which is a vanishingly rare
    // 1-in-2^32 outcome of Linux's RFC 6528 secure_tcp_seq generator.
    bool          cycle1_isn_captured = false;
    bool          cycle2_isn_captured = false;
    std::uint32_t cycle1_isn          = 0U;
    std::uint32_t cycle2_isn          = 0U;

    // RFC 793 §3.1 pseudo-header checksum validation result, mirrored
    // from `TcpFrame::checksum_valid` at decode time. SCXML guards
    // call this through the const-method form rather than reading the
    // member directly because SCE's expression rewriter only handles
    // `captured.method()` on the structured-binding side — see
    // `reference_sce_captured_arg.md`. §4.8.6.2 TCP_CHECKSUM_03 reads
    // this in its single pass guard to verify the DUT-emitted segment
    // checksum is correct per RFC 793 §3.1.
    bool          checksum_valid = false;
    bool tcp_checksum_valid() const noexcept { return checksum_valid; }

    // Wall-clock arrival timestamp of the most-recently-dispatched
    // TcpFrame, in microseconds since the Unix epoch. Mirrored from
    // `TcpFrame::observed_ts_us` by `fillTcpCapturedFromFrame` on
    // every frame regardless of whether the SCXML guard fires — so a
    // failing-cond frame still updates `observed_ts_us` but does NOT
    // disturb `prev_observed_ts_us`.
    std::int64_t observed_ts_us = 0;

    // Wall-clock timestamp of the frame that fired the most recent
    // SCXML transition, in microseconds since the Unix epoch.
    // Auto-managed by `dispatchTcpFrame`: snapshots `observed_ts_us`
    // when `sm.step()` advances `getCurrentState()`. Initial value 0
    // means "no prior fired transition" — first-transition guards
    // must therefore NOT depend on `frame_delta_us()` (the delta
    // would equal `observed_ts_us` itself, an enormous epoch-relative
    // number).
    std::int64_t prev_observed_ts_us = 0;

    // Microsecond delta between the current frame and the
    // most-recently-fired-transition frame. Returns 0 when no prior
    // transition has fired so first-transition guards remain
    // unbiased. §4.8.6.11 RETRANSMISSION_TO_04/_05/_06 use this to
    // gate on RFC 6298 RTO timing — the first transition guards on
    // `is_dut_syn(...)`/`is_dut_data_segment(...)` alone, the second
    // and later guard on `... and frame_delta_us() > N_us` (lower
    // bound that rejects sub-RTO traffic) and optionally
    // `... and frame_delta_us() < M_us` (upper bound to anchor the
    // initial RTO at ~1 s). For backoff cases, monotonically
    // increasing per-state lower bounds rule out a constant-interval
    // ("linear") response: a DUT that retransmits every 1 s passes
    // `frame_delta_us() > 0.8 s` at retx1 but fails the strict
    // `> 1.5 s` at retx2.
    std::int64_t frame_delta_us() const noexcept {
        if (prev_observed_ts_us == 0) {
            return 0;
        }
        return observed_ts_us - prev_observed_ts_us;
    }

    // §4.8.6.2 / §4.8.6.3 share a recurring pass-guard shape: a
    // DUT-origin pure ACK with no payload, distinguished only by
    // (src_ip, dst_ip, src_port, dst_port). CHECKSUM_01/02 plus
    // UNACCEPTABLE_04/06/14 all encoded the same conjunct chain
    // (src_ip == expected.dut_iface_ip and dst_ip ==
    // expected.tester_ip and src_port == X and dst_port == Y and
    // (flags & ACK) != 0 and (flags & SYN/FIN/RST) == 0 and
    // payload_len == 0) verbatim. Wrapping the predicate as a
    // member method collapses each SCXML guard to one
    // `cpp:captured.is_pure_dut_ack(...)` call and removes the
    // verbatim-duplication drift surface. SCE's expression
    // rewriter only handles `captured.method()` form (see
    // `reference_sce_captured_arg.md`), so a free function
    // taking captured by ref would not work here.
    bool is_pure_dut_ack(std::uint32_t expected_dut_iface_ip,
                          std::uint32_t expected_tester_ip,
                          std::uint16_t expected_src_port,
                          std::uint16_t expected_dst_port) const noexcept {
        return src_ip == expected_dut_iface_ip
            && dst_ip == expected_tester_ip
            && src_port == expected_src_port
            && dst_port == expected_dst_port
            && (flags & 0x10U) != 0U
            && (flags & 0x02U) == 0U
            && (flags & 0x01U) == 0U
            && (flags & 0x04U) == 0U
            && payload_len == 0U;
    }

    // §4.8.6.3 UNACCEPTABLE_09/10/12 prelude observation: a DUT-emitted
    // FIN+ACK segment marking active-close (FIN-WAIT-1 / LAST-ACK
    // entry). Distinct from `is_pure_dut_ack` in that the FIN flag is
    // set; the 4-tuple match is identical so SCXML guards stay
    // shape-aligned with the close-elicited-ACK / corrupt-elicited-ACK
    // siblings of the same case.
    //
    // Payload is not constrained — Linux normally emits an empty FIN
    // when close() is called with a drained send buffer, but RFC 793
    // permits FIN piggybacked on a data segment. Allowing payload
    // keeps the guard durable against a future test variant that
    // writes data before close.
    bool is_dut_fin_ack(std::uint32_t expected_dut_iface_ip,
                        std::uint32_t expected_tester_ip,
                        std::uint16_t expected_src_port,
                        std::uint16_t expected_dst_port) const noexcept {
        return src_ip == expected_dut_iface_ip
            && dst_ip == expected_tester_ip
            && src_port == expected_src_port
            && dst_port == expected_dst_port
            && (flags & 0x01U) != 0U
            && (flags & 0x10U) != 0U
            && (flags & 0x02U) == 0U
            && (flags & 0x04U) == 0U;
    }

    // §4.8.6.1 BASICS_11/12 prelude observation: a DUT-emitted RST
    // segment marking the post-2*MSL closed-port path (kernel emits
    // RST when no socket matches the 4-tuple). 4-tuple match plus
    // RST flag — ACK piggyback (RFC 793 §3.4 closed-port behaviour
    // depending on incoming-segment ACK) is permitted, payload is
    // not constrained. Sibling of `is_pure_dut_ack` /
    // `is_dut_fin_ack` for SCXML guard symmetry across the §4.8
    // template-parametrized cases (both replay observations now
    // share the `cpp:captured.<method>(...)` shape, eliminating
    // raw-`&` escape hazards in template substitution sites).
    bool is_dut_rst(std::uint32_t expected_dut_iface_ip,
                    std::uint32_t expected_tester_ip,
                    std::uint16_t expected_src_port,
                    std::uint16_t expected_dst_port) const noexcept {
        return src_ip == expected_dut_iface_ip
            && dst_ip == expected_tester_ip
            && src_port == expected_src_port
            && dst_port == expected_dst_port
            && (flags & 0x04U) != 0U;
    }

    // §4.8.6.6 FLAGS_INVALID_03..06 SYN-SENT prelude observation: a
    // DUT-emitted pure SYN segment marking active-OPEN issuance (or a
    // SYN retransmit while DUT remains in SYN-SENT). 4-tuple match
    // plus SYN set with FIN/RST/ACK clear — distinguishes the active-
    // OPEN initial SYN from the SYN+ACK any tester-side handshake
    // would emit. Used both as positive trigger (case enters its
    // first absence window only after DUT proves SYN-SENT entry on
    // the wire) and as absence-guard "DUT didn't go CLOSED" signal
    // (FLAGS_INVALID_05's pass criterion is "no further SYN retx
    // because DUT cleanly transitioned to CLOSED on RST+acceptable-
    // ACK"). Payload is not constrained — RFC 793 permits SYN+data
    // even though Linux does not emit it normally.
    bool is_dut_syn(std::uint32_t expected_dut_iface_ip,
                    std::uint32_t expected_tester_ip,
                    std::uint16_t expected_src_port,
                    std::uint16_t expected_dst_port) const noexcept {
        return src_ip == expected_dut_iface_ip
            && dst_ip == expected_tester_ip
            && src_port == expected_src_port
            && dst_port == expected_dst_port
            && (flags & 0x02U) != 0U
            && (flags & 0x10U) == 0U
            && (flags & 0x04U) == 0U
            && (flags & 0x01U) == 0U;
    }

    // §4.8.6.9 TCP_MSS_OPTIONS_06/_09/_10 segment-size observation:
    // a DUT-emitted ACK-only data segment (payload_len > 0, ACK set,
    // SYN/FIN/RST clear). PSH may be set or clear — Linux flips PSH
    // on the last segment of a single ::send() call but the spec
    // assertion is on payload_len equality, not control bits. The
    // 4-tuple match isolates the case-specific connection from
    // handshake / FIN segments and from any cross-case ambient
    // traffic; the payload_len > 0 conjunct rules out the pure ACKs
    // that flank the data flow.
    //
    // SCXML usage shape:
    //   <transition cond="cpp:captured.is_dut_data_segment(
    //       expected.dut_iface_ip, expected.tester_ip,
    //       src_port, dst_port) and captured.payload_len == N"
    //       target="pass"/>
    //   <transition cond="cpp:captured.is_dut_data_segment(...)
    //       and captured.payload_len != N"
    //       target="fail_wrong_segment_size"/>
    // Non-data segments fail both conds and stay in-state until the
    // first data segment lands or the deadline fires.
    bool is_dut_data_segment(std::uint32_t expected_dut_iface_ip,
                              std::uint32_t expected_tester_ip,
                              std::uint16_t expected_src_port,
                              std::uint16_t expected_dst_port) const noexcept {
        return src_ip == expected_dut_iface_ip
            && dst_ip == expected_tester_ip
            && src_port == expected_src_port
            && dst_port == expected_dst_port
            && (flags & 0x10U) != 0U
            && (flags & 0x02U) == 0U
            && (flags & 0x01U) == 0U
            && (flags & 0x04U) == 0U
            && payload_len > 0U;
    }
};

// ADL hook for TestRunner<SM>. Captured context fields come from wire
// frames, not CLI — this is a no-op for symmetry with the other
// Named Contexts.
inline void applyTestConfig(TcpCaptured & /*c*/, const TestConfig & /*cfg*/) {}

inline void fillTcpCapturedFromFrame(TcpCaptured &c, const TcpFrame &f) {
    c.src_ip         = f.src_ip;
    c.dst_ip         = f.dst_ip;
    c.src_port       = f.src_port;
    c.dst_port       = f.dst_port;
    c.seq_num        = f.seq_num;
    c.ack_num        = f.ack_num;
    c.data_offset    = f.data_offset;
    c.flags          = f.flags;
    c.window         = f.window;
    c.checksum       = f.checksum;
    c.urgent_pointer = f.urgent_pointer;
    c.payload_len    = f.payload_len;
    c.checksum_valid = f.checksum_valid;
    c.mss            = f.mss;
    c.observed_ts_us = f.observed_ts_us;
}

}  // namespace tc8
