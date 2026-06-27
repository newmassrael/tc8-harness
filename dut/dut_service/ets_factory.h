#pragma once

#include <memory>

namespace tc8::dut {

class EtsImpl;

// Factory for the ETS stub (override seam). The default definition in
// ets_factory.cpp returns a stock EtsImpl. An OEM links a TU that defines this
// symbol with a strong definition (the default is weak) to return its own
// EtsImpl subclass — method-behaviour overrides or extra NDA method handlers —
// WITHOUT forking tc8-harness. See
// claudedocs/ets-dut-public-completion-and-oem-seam-design.md.
std::shared_ptr<EtsImpl> createEtsStub();

}  // namespace tc8::dut
