#include "ets_factory.h"

#include "ets_impl.h"

namespace tc8::dut {

// Weak default — an OEM TU defining a strong createEtsStub() overrides this at
// link time (GCC/Clang weak-symbol model). No OEM TU -> the stock EtsImpl.
__attribute__((weak)) std::shared_ptr<EtsImpl> createEtsStub() {
    return std::make_shared<EtsImpl>();
}

}  // namespace tc8::dut
