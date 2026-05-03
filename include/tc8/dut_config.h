#pragma once

#include <cstdint>

// Identity of this project's *DUT*.
//
// The TC8 v3.0 specification does NOT prescribe concrete values for
// <SERVICE-ID-1>, <SERVICE-ID-1-INSTANCE-ID>, <SERVICE-ID-1-UDP-PORT>, etc.
// (see §5.1.2.3). These are deployment parameters the tester chooses per DUT.
// The constants below are this project's chosen DUT identity and MUST match:
//
//   - dut/dut_service/vsomeip.json
//   - dut/ets/ets.fdepl
//
// Divergence will silently break every case that depends on the DUT being
// reachable under the advertised identity. There is no runtime cross-check
// yet; keep these in sync by hand until a codegen pass subsumes both sides.

namespace tc8::dut {

// SOME/IP service identity.
inline constexpr std::uint16_t kServiceId  = 0xF4E7;
inline constexpr std::uint16_t kInstanceId = 0x0001;

// Endpoints declared in vsomeip.json for the ETS service above.
inline constexpr std::uint16_t kSdPort  = 30490;  // SOME/IP-SD
inline constexpr std::uint16_t kTcpPort = 30501;  // reliable unicast
inline constexpr std::uint16_t kUdpPort = 30502;  // unreliable unicast

// BPF capture window covering the ports above with headroom for extra
// service instances added on adjacent ports. Widened from the historical
// 30490-30500 window, which silently excluded kTcpPort and kUdpPort.
inline constexpr std::uint16_t kCapturePortLow  = 30490;
inline constexpr std::uint16_t kCapturePortHigh = 30510;

}  // namespace tc8::dut
