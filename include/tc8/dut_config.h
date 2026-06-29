#pragma once

#include <cstdint>

// Identity of this project's *DUT*.
//
// The TC8 v3.0 specification does NOT prescribe concrete values for
// <SERVICE-ID-1>, <SERVICE-ID-1-INSTANCE-ID>, <SERVICE-ID-1-UDP-PORT>, etc.
// (see §5.1.2.3). These are deployment parameters the tester chooses per DUT.
// The constants below are this project's chosen DUT identity and MUST match:
//
//   - dut/dut_service/vsomeip.json (the `applications` name and the service /
//     instance / port deployment)
//   - dut/ets/ets.fdepl
//   - the VSOMEIP_APPLICATION_NAME the DUT is launched with (must equal
//     kApplicationName)
//
// Divergence will silently break every case that depends on the DUT being
// reachable under the advertised identity. There is no runtime cross-check
// yet; keep these in sync by hand until a codegen pass subsumes both sides.

namespace tc8::dut {

// vsomeip application DISPLAY name — matches vsomeip.json `applications[].name`
// and the VSOMEIP_APPLICATION_NAME launch env. NOTE: this name does NOT key the
// vsomeip runtime application map. CommonAPI registers the DUT's app under its
// default *connection id* (the empty string), which is how the ETS event-sink
// retrieves the shared application (see dut_service/ets_event_sink.h) — never by
// this display name.
inline constexpr const char* kApplicationName = "tc8-dut";

// SOME/IP service identity.
inline constexpr std::uint16_t kServiceId  = 0xF4E7;
inline constexpr std::uint16_t kInstanceId = 0x0001;

// Endpoints declared in vsomeip.json for the ETS service above.
inline constexpr std::uint16_t kSdPort  = 30490;  // SOME/IP-SD
inline constexpr std::uint16_t kTcpPort = 30501;  // reliable unicast
inline constexpr std::uint16_t kUdpPort = 30502;  // unreliable unicast

// SOME/IP-SD multicast group the DUT and tester exchange Find/Offer on — matches
// vsomeip.json `service-discovery.multicast`. The single C++ source for this value
// (the tester SD emitters default to it); same hand-sync contract as the identity
// above. A `const char*` (not std::string_view) to keep this widely-included
// config header free of <string_view>, mirroring kApplicationName.
inline constexpr const char* kSdMcastGroup = "224.244.224.245";

// BPF capture window covering the ports above with headroom for extra
// service instances added on adjacent ports. Widened from the historical
// 30490-30500 window, which silently excluded kTcpPort and kUdpPort.
inline constexpr std::uint16_t kCapturePortLow  = 30490;
inline constexpr std::uint16_t kCapturePortHigh = 30510;

}  // namespace tc8::dut
