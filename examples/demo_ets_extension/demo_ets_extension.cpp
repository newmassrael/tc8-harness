#include <memory>

#include "demo_ets_extension.h"
#include "ets_extension.h"

// OEM extension-slot demo. Build the DUT with
//   -DTC8_ETS_EXTENSION_SRC=examples/demo_ets_extension/demo_ets_extension.cpp
// (with dut/dut_service on the include path for ets_extension.h) and the DUT
// offers the synthetic demo event surface via the SAME vsomeip application the
// CommonAPI ETS service uses — no second application, no fidl edit. An OEM
// replaces DemoEtsExtension with its own IEtsExtension to offer its NDA surface.
namespace tc8::dut {

std::unique_ptr<IEtsExtension> createEtsExtension() {
    return std::make_unique<DemoEtsExtension>();
}

}  // namespace tc8::dut
