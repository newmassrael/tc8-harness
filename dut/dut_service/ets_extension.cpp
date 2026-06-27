#include "ets_extension.h"

namespace tc8::dut {

namespace {
// No-op default: the public DUT exposes no OEM-proprietary events.
class NullEtsExtension : public IEtsExtension {};
}  // namespace

// Weak default — an OEM TU defining a strong createEtsExtension() overrides
// this at link time (GCC/Clang weak-symbol model).
__attribute__((weak)) std::unique_ptr<IEtsExtension> createEtsExtension() {
    return std::make_unique<NullEtsExtension>();
}

}  // namespace tc8::dut
