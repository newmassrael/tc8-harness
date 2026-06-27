#pragma once

#include <memory>

namespace tc8::dut {

// Extend seam (O2 path) for events/methods the OEM owns but that are NOT in the
// public fidl — e.g. the OEM's NDA event surface. The OEM emits them via raw
// vsomeip offer_event/notify in onRegister/onTick. The in-tree default is a
// no-op so the public DUT builds and behaves unchanged. The complementary O1
// path is the TC8_ETS_FIDL superset-fidl override (CommonAPI-typed). The OEM
// selects its implementation at configure time via TC8_ETS_EXTENSION_SRC — the
// same source-selection idiom as the factory and TC8_ETS_FIDL. See
// claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
//
// Only hooks with a real call site exist (no speculative methods): onRegister
// (after the service is offered), onTick (each DUT main-loop pass), onStop
// (shutdown). A subscribe hook is intentionally absent until the DUT has a
// subscription call site to drive it.
class IEtsExtension {
public:
    virtual ~IEtsExtension() = default;
    virtual void onRegister() {}
    virtual void onTick() {}
    virtual void onStop() {}
};

// Default returns a no-op extension; selected via TC8_ETS_EXTENSION_SRC.
std::unique_ptr<IEtsExtension> createEtsExtension();

}  // namespace tc8::dut
