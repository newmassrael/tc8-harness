#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "ets_extension.h"  // IEtsEventSink

namespace tc8::dut {

// Build a vsomeip-backed IEtsEventSink over the application named `app_name` —
// the CommonAPI ETS service's OWN vsomeip application, retrieved by name so the
// extension shares the one routing client (no second vsomeip application). Events
// and method handlers are scoped to `service`/`instance`. Call only AFTER the
// CommonAPI service is registered (that is what creates the named application).
//
// If the application is not found (e.g. VSOMEIP_APPLICATION_NAME unset, or called
// too early), returns a no-op sink and logs to stderr — the public DUT, whose
// default extension never uses the sink, is unaffected. Never returns null, so
// callers pass `*sink` to the extension hooks unconditionally.
//
// This header stays vsomeip-free; the wrapping of vsomeip::application lives in
// ets_event_sink.cpp.
std::unique_ptr<IEtsEventSink> makeEtsEventSink(const std::string& app_name,
                                                std::uint16_t service,
                                                std::uint16_t instance);

}  // namespace tc8::dut
