#include <memory>

#include "demo_ets_extension.h"
#include "ets_extension.h"

// OEM extension-slot demo. Build the DUT with
//   -DTC8_ETS_EXTENSION_SRC=examples/demo_ets_extension/demo_ets_extension.cpp
// and the DUT offers the synthetic demo event surface via the SAME vsomeip
// application the CommonAPI ETS service uses — no second application, no fidl
// edit. The seam headers resolve because tc8-dut puts dut/dut_service on its
// include path (dut/dut_service/CMakeLists.txt), so any out-of-dir slot file can
// include them. An OEM replaces DemoEtsExtension with its own IEtsExtension.
namespace tc8::dut {

std::unique_ptr<IEtsExtension> createEtsExtension() {
    return std::make_unique<DemoEtsExtension>();
}

}  // namespace tc8::dut
