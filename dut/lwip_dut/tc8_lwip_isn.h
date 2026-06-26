/* Product-neutral seam for seeding the lwIP TCP ISN generator.
 *
 * The shared bring-up (lwip_stack_bringup.cpp — the utm-sdk-lwip reference an OEM
 * replaces) generates a 16-byte secret and hands it here before the first TCP pcb
 * is created. Each product supplies the implementation:
 *   * the conformance DUT drives the lwIP-contrib RFC 6528 generator (the tcp_isn
 *     addon) — tc8_lwip_dut.cpp;
 *   * the UTM drives the self-contained AES-CMAC generator — tc8_lwip_tcp_isn.cpp,
 *     carrying no lwIP-contrib / PPP / MD5 dependency.
 *
 * Keeping the bring-up dependent on this abstraction — not on a concrete generator
 * — is what lets one bring-up serve both products and the exported SDK, and keeps
 * the lwIP-contrib ISN addon out of the UTM's (and the OEM's) link entirely.
 */
#ifndef TC8_LWIP_ISN_H
#define TC8_LWIP_ISN_H

#include <cstdint>

namespace tc8::lwip_dut {

// Seed the TCP ISN generator with a 16-byte secret. Must be called before the
// first TCP pcb is created; the generator is only read thereafter, and the ISN
// hook fires under the lwIP core lock, so no further synchronization is needed.
void SeedTcpIsn(const std::uint8_t secret[16]);

}  // namespace tc8::lwip_dut

#endif  // TC8_LWIP_ISN_H
