#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_l3_endpoints.h"
#include "sce_integration/captured_l4_ports.h"

// Transition trace recording infrastructure (Evidence Export — Option 3).
//
// Each per-case TestRunner<SM> accumulates a TransitionStep on every
// SCXML transition the live state machine fires. The recorded sequence
// is the single source of truth for "what the harness observed" — the
// site-walker (site/scripts/generate_messages.py::_label_via_trace)
// renders the timeline directly from it, bypassing its own cond
// evaluation entirely. This eliminates the dual evidence-base problem
// that drove the honest-disclosure crutches retired in Phase F.
//
// Step content:
//   - ``step_idx``         monotonic counter, 0-based.
//   - ``event_name``       SCXML event id (e.g. "arp_observed",
//                          "deadline_exceeded"). const-pointer-style so
//                          the per-case generated SM's getEventName()
//                          can feed it directly without an allocation.
//   - ``from_state_name``  / ``to_state_name`` — SCXML state ids via
//                          SCE's per-policy getStateName() (upstreamed
//                          to the codegen template; emitted
//                          unconditionally as of this change).
//   - ``pcap_frame_idx``   index into the saved pcap's frame stream, or
//                          -1 when the trigger had no retained frame
//                          (deadline_exceeded, capture-scope shortfall).
//   - ``captured_json``    sparse JSON object of the most-interesting
//                          fields for the family at trace time. The
//                          walker shows these in the verdict-decider
//                          case-note when pcap_frame_idx == -1; never
//                          re-evaluates conds against them, so the
//                          schema can evolve without breaking labels.
//
// Each Captured family contributes a free function
//   void appendCapturedJson(std::string& out, const FooCaptured&)
// declared next to the struct (ADL-resolved from TestRunner<SM>). The
// helper appends a complete JSON object; callers handle separators.

namespace tc8::sce {

struct TransitionStep {
    int          step_idx        = 0;
    const char  *event_name      = "";
    const char  *from_state_name = "";
    const char  *to_state_name   = "";
    int          pcap_frame_idx  = -1;
    std::string  captured_json;
};

// Append ``s`` as a JSON-escaped string body (no surrounding quotes) to
// ``out``. Mirrors the minimal subset of RFC 8259 §7 needed for the
// state/event id strings (control chars, ``"``, ``\``). Keeping the
// helper here avoids dragging an external JSON library into the trait
// surface — every per-family appendCapturedJson uses it for fields that
// might contain quote/backslash (none today; reserved for future
// payload-bytes serialisation).
inline void appendJsonEscaped(std::string &out, std::string_view s) {
    for (char c : s) {
        switch (c) {
            case '"':  out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out.append(buf);
                } else {
                    out.push_back(c);
                }
        }
    }
}

// Append a 6-byte MAC array as a colon-separated lowercase hex string
// (e.g. "86:e1:db:ae:77:f3"). Used by every Captured family's
// appendCapturedJson when emitting sender_hw / eth_src style fields.
template <typename ByteArray>
inline void appendMacJson(std::string &out, const ByteArray &mac) {
    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                  static_cast<unsigned>(mac[0]), static_cast<unsigned>(mac[1]),
                  static_cast<unsigned>(mac[2]), static_cast<unsigned>(mac[3]),
                  static_cast<unsigned>(mac[4]), static_cast<unsigned>(mac[5]));
    out.append(buf);
}

// Append an NBO-stored IPv4 address as a dotted-quad string. Mirrors
// the wire-side semantics: ``ip`` is the uint32 with the wire's first
// octet in the low byte (LE host assumption — same as the rest of the
// harness).
inline void appendIpv4Json(std::string &out, std::uint32_t ip) {
    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "\"%u.%u.%u.%u\"",
                  static_cast<unsigned>(ip & 0xFFu),
                  static_cast<unsigned>((ip >> 8) & 0xFFu),
                  static_cast<unsigned>((ip >> 16) & 0xFFu),
                  static_cast<unsigned>((ip >> 24) & 0xFFu));
    out.append(buf);
}

// Append `<key><decimal>` where ``key`` carries its own leading
// separator and quoting (e.g. ``,"seq_num":``). The single integer
// emitter every per-context appendCapturedJson serialiser shares, in
// place of the identical `emit_u` lambda each used to re-declare locally.
inline void appendUintJson(std::string &out, const char *key, unsigned v) {
    char buf[16];
    out.append(key);
    std::snprintf(buf, sizeof(buf), "%u", v);
    out.append(buf);
}

// Signed 64-bit emitter — timing slots (microsecond timestamps / deltas)
// overflow the 32-bit `appendUintJson`.
inline void appendI64Json(std::string &out, const char *key, std::int64_t v) {
    char buf[24];
    out.append(key);
    std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(v));
    out.append(buf);
}

// Append the universal inter-frame timing observation
// ``,"observed_ts_us":N,"frame_delta_us":N,"delta_from_listen_window_us":N``
// shared by every Named Context that derives from `CapturedFrameTiming`.
// Surfacing the deltas is what makes a timing-window verdict (e.g.
// `dut_*_interval_out_of_range`) self-diagnosing: the witnessing inter-frame
// delta AND the listen-window-relative delta ride the trace, so a failure no
// longer needs a pcap re-run to read the measured value. `frame_delta_us` is
// the frame-to-frame gap (offer-to-offer cases); `delta_from_listen_window_us`
// is the gap from the listen-window-open instant (boot/stimulus-relative
// cases). Both read 0 until the case that needs them fires (mirrors
// `frame_delta_us`'s first-transition 0). Leading comma — callers append it
// after the family's own fields.
inline void appendTimingJson(std::string &out, const ::tc8::CapturedFrameTiming &t) {
    appendI64Json(out, ",\"observed_ts_us\":", t.observed_ts_us);
    appendI64Json(out, ",\"frame_delta_us\":", t.frame_delta_us());
    appendI64Json(out, ",\"delta_from_listen_window_us\":",
                  t.delta_from_listen_window_us());
}

// Append the L3 endpoint pair as ``"src_ip":<ip>,"dst_ip":<ip>`` — no
// surrounding brace or separator, so the caller controls whether it
// follows ``{`` (endpoints first) or ``,`` (endpoints mid-object). The
// one place the dotted-quad src/dst emission lives, shared by every Named
// Context that derives from CapturedL3Endpoints (TCP / UDP / SOME/IP /
// DHCPv4 / ICMPv4) instead of each re-inlining the two appendIpv4Json
// calls and key literals.
inline void appendL3EndpointsJson(std::string &out,
                                  const tc8::CapturedL3Endpoints &e) {
    out.append("\"src_ip\":");
    appendIpv4Json(out, e.src_ip);
    out.append(",\"dst_ip\":");
    appendIpv4Json(out, e.dst_ip);
}

// Append the L4 port pair as ``,"src_port":N,"dst_port":N`` (leading
// separator, since the ports always immediately follow the L3 pair).
// Shared by every Named Context that derives from CapturedL4Ports
// (TCP / UDP / SOME/IP / DHCPv4).
inline void appendL4PortsJson(std::string &out,
                              const tc8::CapturedL4Ports &p) {
    appendUintJson(out, ",\"src_port\":", p.src_port);
    appendUintJson(out, ",\"dst_port\":", p.dst_port);
}

}  // namespace tc8::sce
