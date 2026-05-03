#pragma once

#include <variant>

#include "tc8/captured_event.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"
#include "tc8/protocol_frames/udp_frame.h"

#include "dhcpv4_captured.h"
#include "udp_and_dhcpv4_captured.h"
#include "udp_captured.h"

namespace tc8::sce {

// Cross-protocol dispatcher for §4.7.6.7 CM_05/_06. The packet
// pipeline emits BOTH a `UdpFrame` and (for BOOTP-shaped packets on
// port 67/68) a `Dhcpv4Frame` per UDP datagram, so a single OFFER /
// ACK lands as two events in succession. The dispatcher steers each
// variant into its respective sub-context:
//
//   * `Dhcpv4Frame` → `c.dhcpv4`, raise `Dhcp_observed`. ACK / NAK /
//     DECLINE timestamp surfaces snapshot in lock-step with the
//     single-protocol `dispatchDhcpv4Frame` so cross-protocol guards
//     reading `last_*_observed_ts_us` see the same landmarks.
//
//   * `UdpFrame` → `c.udp`, raise `Udp_observed`. The pre-raise
//     `prev_observed_ts_us` snapshot follows the same fired-transition
//     semantics as `dispatchUdpFrame` so frame-delta predicates work.
//
// SCXML cases declare both event symbols and gate the matching
// transition with the appropriate sub-context predicate.
template <typename SM>
inline void dispatchUdpAndDhcpv4Frame(typename SM::CapturedType& c, SM& sm,
                                      const ::tc8::CapturedEvent& ev) {
    if (const auto* d = std::get_if<::tc8::Dhcpv4Frame>(&ev)) {
        ::tc8::fillDhcpv4CapturedFromFrame(c.dhcpv4, *d);
        // Mirror `dispatchDhcpv4Frame`'s symmetric ACK / NAK / DECLINE
        // timestamp snapshots — pre-raise placement so observers that
        // do not satisfy the current cond still update the slots.
        if (c.dhcpv4.op == 2U && c.dhcpv4.message_type == 5U) {
            c.dhcpv4.last_ack_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        if (c.dhcpv4.op == 2U && c.dhcpv4.message_type == 6U) {
            c.dhcpv4.last_nak_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        if (c.dhcpv4.op == 1U && c.dhcpv4.message_type == 4U) {
            c.dhcpv4.last_decline_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        const auto state_before = sm.getCurrentState();
        sm.raiseExternal(SM::PolicyType::Event::Dhcp_observed);
        sm.step();
        const auto state_after = sm.getCurrentState();
        if (state_after != state_before) {
            c.dhcpv4.prev_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        return;
    }
    if (const auto* u = std::get_if<::tc8::UdpFrame>(&ev)) {
        ::tc8::fillUdpCapturedFromFrame(c.udp, *u);
        const auto state_before = sm.getCurrentState();
        sm.raiseExternal(SM::PolicyType::Event::Udp_observed);
        sm.step();
        const auto state_after = sm.getCurrentState();
        if (state_after != state_before) {
            c.udp.prev_observed_ts_us = c.udp.observed_ts_us;
        }
        return;
    }
}

}  // namespace tc8::sce
