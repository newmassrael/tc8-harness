#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "sce_integration/dut_capabilities.h"
#include "sce_integration/dut_control_backend.h"
#include "sce_integration/dut_control_seams.h"
#include "sce_integration/dut_service_primitive_control.h"

// Link-time registration of DUT-control seams a consumer provides for its own DUT.
//
// The seams a case reaches are the ones a backend implements, and a DUT can serve
// primitives this repository has no numbers for (PRS_TPSP reserves groups without
// defining their primitives, and lets a group define its own). The harness cannot
// implement those seams without the numbers and must not hold them. An extension is
// how the numbers stay with the DUT's owner: the owner's translation unit, linked
// into the runner the way extra cases are, registers a factory, and the factory
// builds the sub-interfaces that speak the owner's primitives.
//
//     TC8_REGISTER_DUT_CONTROL_EXTENSION(
//         ::tc8::sce::DutControlBackend::kTestability,
//         [](::tc8::sce::IServicePrimitiveControl &transport) {
//             return std::make_unique<MyDutExtension>(transport);
//         });
//
// What an extension is handed is the backend's service-primitive call, bound to the
// run's endpoint, timeout and source address, and nothing else: it cannot drift from
// the control channel the run uses, and the control-plane exclusion that already
// keeps that channel out of verdicts covers it.
//
// The rules are the composition's (dut_control_compose.h), stated here because they
// are the contract an extension is written to:
//   - An extension offers a seam the backend does not. One that offers a seam the
//     backend already provides, or that another extension provides, is a startup
//     error and not an override.
//   - Its capabilities() are the bits for the seams it provides, no more and no
//     fewer; a claim wider than its answer is a startup error, because the gate would
//     run cases into a nullptr instead of skipping them.
//   - Registration order decides nothing, since two claims on a seam cannot both
//     stand. The run header names the extension behind each seam.

namespace tc8::sce {

// What an extension provides: any of the optional seams (the list a backend shares)
// and the capability bits that go with them.
class DutControlExtension : public IDutControlSeams {
public:
    ~DutControlExtension() override = default;

    // Names this extension in the run header and in startup errors.
    virtual std::string_view name() const = 0;

    // The DutCapability bits for the seams this extension provides.
    virtual DutCapabilities capabilities() const = 0;
};

using DutControlExtensionFactory =
    std::function<std::unique_ptr<DutControlExtension>(IServicePrimitiveControl &transport)>;

struct DutControlExtensionRegistration {
    DutControlBackend backend;
    DutControlExtensionFactory make;
};

class DutControlExtensionRegistry {
public:
    static DutControlExtensionRegistry &instance() {
        static DutControlExtensionRegistry registry;
        return registry;
    }

    void add(DutControlBackend backend, DutControlExtensionFactory make) {
        registrations_.push_back({backend, std::move(make)});
    }

    const std::vector<DutControlExtensionRegistration> &all() const { return registrations_; }

private:
    std::vector<DutControlExtensionRegistration> registrations_;
};

struct DutControlExtensionRegistrar {
    DutControlExtensionRegistrar(DutControlBackend backend, DutControlExtensionFactory make) {
        DutControlExtensionRegistry::instance().add(backend, std::move(make));
    }
};

// A registration the run cannot honour. Thrown while the backend is being built, so
// it ends the run before any case sends anything.
class DutControlExtensionError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

}  // namespace tc8::sce

#define TC8_DUT_EXT_CONCAT_INNER(a, b) a##b
#define TC8_DUT_EXT_CONCAT(a, b) TC8_DUT_EXT_CONCAT_INNER(a, b)
#define TC8_REGISTER_DUT_CONTROL_EXTENSION(backend, factory)                        \
    static const ::tc8::sce::DutControlExtensionRegistrar TC8_DUT_EXT_CONCAT(       \
        tc8_dut_control_extension_registrar_, __COUNTER__)(backend, factory)
