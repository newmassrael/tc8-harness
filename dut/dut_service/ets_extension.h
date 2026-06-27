#pragma once

#include <cstdint>
#include <memory>

namespace tc8::dut {

// Extend seam (O2 path) for events/methods the OEM owns but that are NOT in the
// public fidl — e.g. the OEM's NDA event surface. The OEM emits them via
// raw vsomeip offer_event/notify in onRegister/onTick (or via its own CommonAPI
// superset stub). The in-tree default is a no-op so the public DUT builds and
// behaves unchanged. The complementary O1 path is the TC8_ETS_FIDL superset-
// fidl override (CommonAPI-typed). See
// claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
class IEtsExtension {
public:
    virtual ~IEtsExtension() = default;

    // Once after the public service is registered: offer additional vsomeip
    // events/services here.
    virtual void onRegister() {}
    // An eventgroup was subscribed: emit OEM initial data.
    virtual void onSubscribe(std::uint16_t /*eventgroup*/) {}
    // Periodic tick from the DUT main loop: OEM cyclic notify().
    virtual void onTick() {}
    // Shutdown.
    virtual void onStop() {}
};

// Weak default returns a no-op extension; an OEM TU defining a strong
// createEtsExtension() overrides it at link time.
std::unique_ptr<IEtsExtension> createEtsExtension();

}  // namespace tc8::dut
