#pragma once

#include <memory>

namespace tc8::dut {

class EtsImpl;

// Factory for the ETS stub (override seam). The default definition lives in
// ets_factory.cpp and returns a stock EtsImpl. An OEM overrides the behaviour by
// pointing TC8_ETS_FACTORY_SRC at its own translation unit (which returns its
// EtsImpl subclass) — the same compile-time source-selection idiom as
// TC8_ETS_FIDL and TC8_CASE_OVERRIDE_DIRS, so there is ONE injection philosophy.
// See claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
std::shared_ptr<EtsImpl> createEtsStub();

}  // namespace tc8::dut
