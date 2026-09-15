#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "tc8/testability/middleware.h"
#include "utm_module_sm.h"

namespace tc8::scxml_module {

// The hand-written half of an Upper-Tester middleware module whose sequencing is
// authored in utm_module.scxml and emitted to C++ by SCE.
//
// Everything this class does is translation, and that is the point. Each
// MiddlewareModule callback raises one event on the generated machine, and
// onPrimitive() projects the machine's resulting state onto a PRS_TPSP Result
// ID. There is no guard, no flag and no ordering check here — delete a
// transition from the SCXML and the answers change with this file untouched,
// which is the property R1 of the requirements document asks for.
//
// Scope note: this machine has no data plane. It opens no socket, arms no timer
// and emits no asynchronous Event, so onStart() has nothing to acquire and the
// engine is initialized at construction instead. A module that does own a data
// plane keeps the same shape and does that work in onStart(), as
// examples/demo_middleware_module does.
class UtmModule : public tc8::testability::MiddlewareModule {
public:
    using Machine = ::SCE::Generated::utm_module::utm_module;

    // OEM-reserved service group (PRS_TPSP §6.6 counts down from 0x7F; the
    // synthetic demo module already holds 0x7F). Fabricated, like every value in
    // examples/ — a real module injects its own from configuration.
    static constexpr std::uint8_t kGroup = 0x7E;

    // The one primitive this machine sequences.
    static constexpr std::uint8_t kPidPing = 0x01;

    UtmModule();

    std::vector<std::uint8_t> groups() const override;
    void onStart(tc8::testability::MiddlewareContext &ctx) override;
    void onStop() override;
    void onPrimitive(const tc8::testability::Header &req, const std::uint8_t *dat,
                     std::size_t dat_len, const tc8::net::Endpoint &peer,
                     std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat) override;
    void onStartTest() override;
    void onEndTest() override;

private:
    Machine sm_;
};

}  // namespace tc8::scxml_module
