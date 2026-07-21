#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/dhcpv4_default_endpoints.h"  // kDefault*Be
#include "sce_integration/test_case_traits.h"  // IStimulusScheduler
#include "sce_integration/test_config.h"
#include "stimulus/arp_builder.h"  // sendRawEthernet
#include "stimulus/dhcpv4_frame_builder.h"

namespace tc8::sce::dhcpv4 {

using ::tc8::sce::IStimulusScheduler;

struct ServerEmulParams {
    std::uint32_t server_id_be       = kDefaultServerIdBe;
    std::uint32_t offered_ip_be      = kDefaultOfferedIpBe;
    std::uint32_t subnet_mask_be     = kDefaultSubnetMaskBe;
    std::uint32_t lease_time_seconds = kDefaultLeaseTimeSeconds;
    // §4.7.6.1 SUMMARY_03: server emul appends RFC 2131 §3 PAD options
    // before END so the IPv4 datagram reaches this size. 0 = natural
    // length (default).
    std::uint16_t ip_datagram_total_bytes = 0;
    // §4.7.6.1 SUMMARY_02: forge OFFER's xid as `c.xid + xid_offset`
    // so a multi-server scenario can emit a deliberately-mismatched
    // OFFER (offset != 0) that the DUT MUST silently discard per
    // RFC 2131 §4.3.1. 0 = matched xid (default).
    std::int32_t  xid_offset = 0;

    // §4.7.6.7 CM_05/_06 / RFC 2132 §9.3 Option Overload. Threaded
    // verbatim into `Dhcpv4ReplySpec`; defaults preserve every
    // existing case's legacy "no overload, zero-filled sname/file"
    // wire shape.
    std::uint8_t              option_52_overload = 0;
    std::vector<std::uint8_t> sname_payload;
    std::vector<std::uint8_t> file_payload;
};

// §4.7 lifecycle observer helper. Registers a state-entry observer on
// `target_state_id` (typically `Listening_for_request`, entered by the
// SCXML after observing the DUT's DISCOVER). On entry the closure
// reads the just-captured DUT request's xid + chaddr from `c` and
// emits a BOOTREPLY of `message_type` (2 = OFFER, 5 = ACK) carrying
// the configured server identity + offered IP.
//
// Captured by reference because xid + chaddr are wire-derived and
// known only at fire time; the SCE Captured Named Context is owned
// by the runner for the case's lifetime, so the reference outlives
// the closure.
template <typename Captured>
inline void scheduleDhcpReplyOnStateEntry(
    IStimulusScheduler& scheduler,
    int                 target_state_id,
    std::string_view    iface,
    Captured&           c,
    std::uint8_t        message_type,
    const ServerEmulParams& params = {}) {
    const auto iface_copy = std::string(iface);
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [iface_copy, &c, message_type, params]() {
            ::tc8::stimulus::Dhcpv4ReplySpec spec{};
            spec.eth_dst       = ::tc8::stimulus::kEthBroadcast;
            spec.eth_src       = ::tc8::stimulus::kTesterInjectedMac;
            spec.src_ip_be     = params.server_id_be;
            spec.dst_ip_be     = 0xFFFFFFFFU;
            spec.xid           = c.xid + static_cast<std::uint32_t>(params.xid_offset);
            for (std::size_t i = 0; i < 6; ++i) {
                spec.chaddr[i] = c.chaddr[i];
            }
            spec.message_type       = message_type;
            spec.yiaddr_be          = params.offered_ip_be;
            spec.server_id_be       = params.server_id_be;
            spec.lease_time_seconds = params.lease_time_seconds;
            spec.subnet_mask_be     = params.subnet_mask_be;
            spec.ip_datagram_total_bytes = params.ip_datagram_total_bytes;
            spec.option_52_overload = params.option_52_overload;
            spec.sname_payload      = params.sname_payload;
            spec.file_payload       = params.file_payload;

            const auto frame = ::tc8::stimulus::buildDhcpv4Reply(spec);
            ::tc8::stimulus::sendRawEthernet(frame, iface_copy);
        });
}

// §4.7.6.9 INIT_ALLOC_09 ARP conflict injector. Registers a state-entry
// observer that emits an ARP Reply (opcode=2) with sender_ip equal to
// the DUT's offered yiaddr but from a non-DUT MAC — RFC 2131 §4.4.1
// "address appears to be in use" trigger for the post-Probe listener.
// The DUT's runArpProbeListener observes the Reply (sender_proto_ip ==
// probed_ip from a non-DUT hardware address), returns conflict-true,
// and the runLoop emits DHCPDECLINE.
//
// The conflict MAC is locally-administered (locally-set bit set in
// the first octet) so it cannot collide with any factory-assigned NIC.
// eth_dst targets the DUT iface MAC (RFC 826 unicast Reply convention)
// since the ARP Reply is "to the prober"; AF_PACKET ETH_P_ARP delivers
// regardless of eth_dst, so the choice is cosmetic.
inline void scheduleArpConflictReplyOnStateEntry(
    IStimulusScheduler&                 scheduler,
    int                                 target_state_id,
    std::string_view                    iface,
    const std::array<std::uint8_t, 6>&  dut_mac,
    std::uint32_t                       offered_ip_be) {
    const auto iface_copy = std::string(iface);
    scheduler.scheduleAfterStateEntry(
        target_state_id,
        [iface_copy, dut_mac, offered_ip_be]() {
            ::tc8::stimulus::ArpFrameSpec spec{};
            spec.opcode       = 0x0002;  // Reply
            spec.eth_dst      = dut_mac;
            spec.sender_hw    = {0x02, 0x00, 0xDE, 0xAD, 0x00, 0x01};
            spec.sender_ip_be = offered_ip_be;
            spec.target_hw    = dut_mac;
            spec.target_ip_be = 0U;
            const auto frame = ::tc8::stimulus::buildArpFrame(spec);
            ::tc8::stimulus::sendRawEthernet(frame, iface_copy);
        });
}

// §4.7 cross-message snapshot helper. Registers a state-entry observer
// that calls `c.snapshotDiscoverFields()` when the SM transitions into
// `target_state_id` (typically `Listening_for_request`). The DUT-emitted
// DISCOVER's `secs` and Option 55 bytes are copied into the Captured
// snapshot slots so subsequent REQUEST guards (PARAMETERS_04, ALLOC_04)
// can compare REQUEST fields against the originating DISCOVER's fields.
//
// Observer callbacks run during `sm.step()` while the wire-derived
// `c.options_data` view still points at the DISCOVER's pcap blob; the
// snapshot must therefore fire BEFORE the next dispatcher iteration
// overwrites the wire-derived block with the REQUEST.
template <typename Captured>
inline void scheduleDiscoverSnapshotOnStateEntry(
    IStimulusScheduler& scheduler,
    int                 target_state_id,
    Captured&           c) {
    scheduler.scheduleAfterStateEntry(target_state_id,
                                      [&c]() { c.snapshotDiscoverFields(); });
}

}  // namespace tc8::sce::dhcpv4
