#pragma once

#include <cstdint>
#include <string>

#include "sce_integration/captured_trace.h"
#include "sce_integration/someip_captured.h"

// Captured contexts that belong to ONE SOME/IP case each.
//
// A slot a single case writes from its stimulus and reads in its SCXML is part of
// that case, not of SomeIpCaptured: on the shared struct every SOME/IP case and
// every consumer case could reach it, and a consumer's cases came to depend on one
// (they wrote SOMEIP_ETS_097's handshake flag) until the case changed it. Here each
// case owns its slots in its own type, named after the case, which its SCXML
// declares as the `captured` context (`cpp:type`, `cpp:include`). The type IS-A
// SomeIpCaptured, so the shared dispatch fills it and every shared guard still
// reads; nothing else names it.
//
// Every slot here is written by the case's stimulus or its own dispatch, never by
// fillSomeIpCapturedFromFrame, so it keeps its value across SOME/IP frames.

namespace tc8 {

// SOMEIP_ETS_037: the tester's TCP socket state, `getsockopt(SOL_TCP,
// TCP_INFO).tcpi_state` read after the post-reset observation window.
// TCP_ESTABLISHED (1) means the DUT did not emit FIN, as required; TCP_CLOSE_WAIT
// (8) means it did. 0 until the stimulus reads it.
struct SomeIpEts037Captured : SomeIpCaptured {
    std::uint8_t tcp_peer_state = 0;
};

// SOMEIP_ETS_081: how many TCP connections the DUT opened to the tester's listener;
// ">= 2" is the DUT having renewed its connection after the server reboot.
struct SomeIpEts081Captured : SomeIpCaptured {
    std::uint8_t tcp_handshake_count = 0;
};

// SOMEIP_ETS_097: was the DUT's reconnect an answer to the tester's second Offer?
// Pcap-domain microseconds (`CapturedFrameTiming::observed_ts_us`):
//   - reconnect_offer_ts_us: when the stimulus sent the second Offer; 0 if it
//     never did.
//   - spontaneous_retry_earliest_ts_us: the earliest instant the DUT's own retry
//     timer, as the stimulus measured it while refusing, could fire again. 0 when
//     the DUT was observed quiet for a whole window instead, so none is due.
//   - dut_syn_ts_us: the arrival of the DUT SYN being dispatched, written just
//     before its `dut_reconnect_syn` event.
struct SomeIpEts097Captured : SomeIpCaptured {
    std::int64_t reconnect_offer_ts_us = 0;
    std::int64_t spontaneous_retry_earliest_ts_us = 0;
    std::int64_t dut_syn_ts_us = 0;
};

// The trace records each case's own slots beside the shared ones, so a verdict
// shows what it was judged against.
inline void appendCapturedJson(std::string &out, const SomeIpEts037Captured &c) {
    out.append("{");
    appendSomeIpCapturedMembersJson(out, c);
    ::tc8::sce::appendUintJson(out, ",\"tcp_peer_state\":", c.tcp_peer_state);
    out.append("}");
}

inline void appendCapturedJson(std::string &out, const SomeIpEts081Captured &c) {
    out.append("{");
    appendSomeIpCapturedMembersJson(out, c);
    ::tc8::sce::appendUintJson(out, ",\"tcp_handshake_count\":", c.tcp_handshake_count);
    out.append("}");
}

inline void appendCapturedJson(std::string &out, const SomeIpEts097Captured &c) {
    out.append("{");
    appendSomeIpCapturedMembersJson(out, c);
    ::tc8::sce::appendI64Json(out, ",\"reconnect_offer_ts_us\":", c.reconnect_offer_ts_us);
    ::tc8::sce::appendI64Json(out, ",\"spontaneous_retry_earliest_ts_us\":",
                              c.spontaneous_retry_earliest_ts_us);
    ::tc8::sce::appendI64Json(out, ",\"dut_syn_ts_us\":", c.dut_syn_ts_us);
    out.append("}");
}

}  // namespace tc8
