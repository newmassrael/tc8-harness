#pragma once

#include <cstdint>

namespace tc8 {

// The DUT's SOME/IP service identity — what a stimulus ADDRESSES a request to,
// as opposed to what an SCXML grades an observed frame against. Third member of
// the family with `DutIdentity` and `TesterIdentity`, and it exists for the same
// reason they do: an expectation is a value a `--negative` row rewrites, and a
// row that also redirects the stimulus silences the DUT instead of faulting the
// comparison.
//
// ⚠ The DUT's IPv4 address is deliberately NOT here. It is already
// `DutIdentity::ip`, and `someip.dut_iface_ip` holds the same value as the
// expectation half — 24 stimulus sites read the expectation only because the
// identity was not offered to them. Adding a second copy here would be the
// duplicate this family exists to remove.
//
// What made this the last of the five: ONWIRE_01 grades the response's source
// endpoint, which is the endpoint its own request was sent to, and RPC_18 grades
// an error's echoed service id while its first phase waits for an OfferService
// filtered on that same id. Both looked structurally unfaultable — "the graded
// value IS the addressed value" — and both were only fields nobody had split
// (docs/tech-debt.md TD-54).
struct SomeIpIdentity {
    // The DUT's service ports, host byte order. What `someipUdpMethodDest` /
    // `someipTcpMethodDest` send a Method Request to.
    std::uint16_t udp_port = 0;
    std::uint16_t tcp_port = 0;
    // The service the tester is talking TO. Distinct from the `service_id`
    // expectation that 186 SCXMLs compare an observed frame's field against.
    std::uint16_t service_id = 0;
    std::uint16_t instance_id = 0;
};

}  // namespace tc8
