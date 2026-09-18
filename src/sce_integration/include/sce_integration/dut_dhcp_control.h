#pragma once

#include <cstdint>

// DHCP client-lifecycle sub-interface of the Tier-2 DUT-control seam.
//
// Kept in its own header, next to dut_socket_control.h rather than inside it,
// because starting a DHCP client is not socket-shaped: there is no handle, no
// endpoint pair, and the DUT runs a whole lifecycle rather than performing one
// transfer. Keeping it separate also keeps the include light — the ~90 DHCPv4
// case headers that need the vocabulary do not pull the socket sub-interfaces.

namespace tc8::sce::dhcpv4 {

// OpStartDhcpClient envelope. A config struct (not a 15-positional-param
// signature) so a call site sets only the fields it overrides — the common call
// keeps the fast-envelope defaults, and adding a knob never re-orders an
// existing call. Field names match the wire slots. (C++17: named-field
// assignment, not C++20 designated init.)
//
// This lives at the SEAM rather than beside the stimulus helper that used to own
// it, because it is now the vocabulary BOTH the helper and every backend speak.
// One definition, so a new slot cannot be added to the ask without every
// implementation seeing it.
// Per-field spec provenance — which case each slot exists for — is documented
// once at the wire SSOT, beside `buildStartDhcpClientRequest`
// (stimulus/upper_tester_client.h). It is deliberately not restated here: a
// second copy of a section reference is a second thing to keep in step, and the
// slot names below are the same names that header uses.
struct Dhcpv4StartConfig {
    std::uint8_t  retry_count                = 1;
    std::uint16_t retry_interval_ms          = 1000;
    // NAK -> DISCOVER desync window (RFC 2131 4.4.1).
    std::uint16_t nak_to_discover_min_ms     = 0;
    std::uint16_t nak_to_discover_max_ms     = 0;
    // Post-BOUND ARP Probe listen window.
    std::uint16_t arp_probe_listen_ms        = 0;
    // Post-DECLINE restart window (RFC 2131 3.1).
    std::uint16_t decline_to_discover_min_ms = 0;
    std::uint16_t decline_to_discover_max_ms = 0;
    // Exponential-backoff retransmission envelope.
    std::uint16_t retx_first_ms              = 0;
    std::uint16_t retx_cap_ms                = 0;
    std::uint16_t retx_jitter_ms             = 0;
    // Selects which DHCP client instance runs, for the dual-interface topology.
    std::uint8_t  iface_index                = 0;
    // False when the 1.5 s pilot wait was already paid by an earlier call. A
    // tester-side delay, honoured by the caller rather than the backend.
    bool          apply_initial_wait         = true;
    // Phase F fault-injection flavor byte (kDhcpFlavor*). The wire shape is
    // identical for a positive and a `_neg`; only this value differs, which is
    // why one seam operation covers both.
    std::uint8_t  flavor                     = 0;
};

}  // namespace tc8::sce::dhcpv4

namespace tc8::sce {

// Make the DUT run a DHCP client. The harness cannot provoke this from the wire
// — a DHCP client starts because something told the DUT to start it — so a case
// that needs it is only measurable on a backend providing this sub-interface.
class IDhcpClientControl {
public:
    virtual ~IDhcpClientControl() = default;

    // Start the client with `spec`'s lifecycle envelope. true when the DUT
    // accepted the request; false means the ask did not happen, which is a
    // non-conclusion rather than a DUT verdict.
    virtual bool startClient(const dhcpv4::Dhcpv4StartConfig &spec) = 0;
};

}  // namespace tc8::sce
