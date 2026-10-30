#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

#include "sce_integration/dut_control_extension.h"

namespace tc8::sce::demo {

// Synthetic, NON-NDA demonstration of a DUT-control extension: a copy-paste starter
// for a DUT's owner who serves a TCP-state primitive of its own over the testability
// transport and wants cases that declare kCapTcpStateQuery to run against it.
//
// The group and primitive numbers and the DAT layout are the owner's, which is the
// point of an extension: they live here, in the owner's translation unit, and the
// harness never holds them. These are invented, outside any group PRS_TPSP defines.
//
//   request  DAT: socketId  u16
//   response DAT: state     u8   (the DUT's own numbering, mapped below)
inline constexpr std::uint8_t kDemoGid = 0x7E;
inline constexpr std::uint8_t kDemoPidQueryState = 0x01;

// The DUT's numbering of RFC 793 states, as it reports them in the response.
inline constexpr std::uint8_t kDemoStateClosed = 0;
inline constexpr std::uint8_t kDemoStateListen = 1;
inline constexpr std::uint8_t kDemoStateSynSent = 2;
inline constexpr std::uint8_t kDemoStateSynReceived = 3;
inline constexpr std::uint8_t kDemoStateEstablished = 4;
inline constexpr std::uint8_t kDemoStateFinWait1 = 5;
inline constexpr std::uint8_t kDemoStateFinWait2 = 6;
inline constexpr std::uint8_t kDemoStateCloseWait = 7;
inline constexpr std::uint8_t kDemoStateClosing = 8;
inline constexpr std::uint8_t kDemoStateLastAck = 9;
inline constexpr std::uint8_t kDemoStateTimeWait = 10;

// Translate the DUT's numbering. nullopt for a value it does not define: an answer the
// seam cannot read is a failed query, not a guess.
std::optional<DutTcpState> mapDemoState(std::uint8_t value);

// The extension a registration would build. `mislabel_established` makes it report an
// ESTABLISHED socket as CLOSED while still claiming the state query: the negative
// control, proving the harness reads the extension's answer and not its claim.
std::unique_ptr<DutControlExtension> makeDemoDutExtension(IServicePrimitiveControl &transport,
                                                          bool mislabel_established = false);

// To use it in a runner, register it from a translation unit linked into the runner:
//
//   TC8_REGISTER_DUT_CONTROL_EXTENSION(
//       ::tc8::sce::DutControlBackend::kTestability,
//       [](::tc8::sce::IServicePrimitiveControl &transport) {
//           return ::tc8::sce::demo::makeDemoDutExtension(transport);
//       });
//
// It is not registered here: a registration in this tree would be offered to every
// testability run.

}  // namespace tc8::sce::demo
