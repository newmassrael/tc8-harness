#include "ets_extension.h"

namespace tc8::dut {

namespace {
// No-op default: the public DUT exposes no OEM-proprietary events.
class NullEtsExtension : public IEtsExtension {};
}  // namespace

// Default extension. Selected at configure time via TC8_ETS_EXTENSION_SRC; an
// OEM builds its own source in this slot to return its extension — see header.
std::unique_ptr<IEtsExtension> createEtsExtension() {
    return std::make_unique<NullEtsExtension>();
}

}  // namespace tc8::dut
