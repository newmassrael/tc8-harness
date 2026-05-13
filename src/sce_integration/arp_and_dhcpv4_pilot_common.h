#pragma once

#include <variant>

#include "tc8/captured_event.h"
#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"

#include "arp_captured.h"
#include "arp_and_dhcpv4_captured.h"
#include "dhcpv4_captured.h"

namespace tc8::sce {

// Cross-protocol dispatcher for §4.5.6.1 IPv4_AUTOCONF_INTRO_01 and
// future cases that bind the `ArpAndDhcpv4Captured` Named Context.
//
// On `ArpFrame`: copies the wire fields into `c.arp` via the existing
// `fillArpCapturedFromFrame` helper, then raises `Arp_observed`. On
// `Dhcpv4Frame`: copies into `c.dhcpv4` via `fillDhcpv4CapturedFromFrame`
// and raises `Dhcp_observed`. Both events are explicit — single-protocol
// dispatch helpers (`dispatchArpFrame`, `dispatchDhcpv4Frame`) raise the
// same names; cross-protocol cases declare both event symbols in their
// SCXML and gate the matching transition with the appropriate
// sub-context predicate.
//
// Inter-frame timing: each protocol manages its own `prev_observed_ts_us`
// inside its sub-context, mirroring the existing single-protocol
// behaviour. ARP-side `prev_observed_ts_us` updates are still the
// caller's responsibility (consistent with §4.2 inline dispatch
// convention); §4.7 frame timing stays auto-managed.
template <typename SM>
inline void dispatchArpAndDhcpv4Frame(typename SM::CapturedType& c, SM& sm,
                                      const ::tc8::CapturedEvent& ev) {
    if (const auto* a = std::get_if<::tc8::ArpFrame>(&ev)) {
        ::tc8::fillArpCapturedFromFrame(c.arp, *a);
        sm.raiseExternal(SM::PolicyType::Event::Arp_observed);
        sm.step();
        return;
    }
    if (const auto* d = std::get_if<::tc8::Dhcpv4Frame>(&ev)) {
        ::tc8::fillDhcpv4CapturedFromFrame(c.dhcpv4, *d);
        // Mirror `dispatchDhcpv4Frame`'s symmetric ACK / NAK timestamp
        // snapshots so cross-protocol cases that read
        // `ack_to_request_within_us` / `nak_to_discover_within_us` see
        // the same landmark surface. Pre-raise placement matches the
        // single-protocol dispatcher: state-3 ACK/NAK injections that
        // do not satisfy the current cond still update the slots.
        if (c.dhcpv4.op == 2U && c.dhcpv4.message_type == 5U) {
            c.dhcpv4.last_ack_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        if (c.dhcpv4.op == 2U && c.dhcpv4.message_type == 6U) {
            c.dhcpv4.last_nak_observed_ts_us = c.dhcpv4.observed_ts_us;
        }
        // §4.7.6.3 ALLOCATING_08 timing surface (cross-protocol). DECLINE
        // is BOOTREQUEST (op=1) — distinct condition from the ACK/NAK
        // BOOTREPLY guards above. Cross-protocol cluster (ALLOCATING_07/_08)
        // shares this landmark with the single-protocol dispatcher.
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
}

}  // namespace tc8::sce
