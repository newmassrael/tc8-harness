#include "utm_module_adapter.h"

#include "tc8/testability_protocol.h"

namespace tc8::scxml_module {
namespace {

namespace gen = ::SCE::Generated::utm_module;

}  // namespace

UtmModule::UtmModule() {
    sm_.initialize();
}

std::vector<std::uint8_t> UtmModule::groups() const {
    return {kGroup};
}

void UtmModule::onStart(tc8::testability::MiddlewareContext & /*ctx*/) {
    // Nothing to acquire: this machine has no data plane (see the class comment).
}

void UtmModule::onStop() {}

void UtmModule::onStartTest() {
    sm_.processEvent(gen::Event::Start_test);
}

void UtmModule::onEndTest() {
    sm_.processEvent(gen::Event::End_test);
}

void UtmModule::onPrimitive(const tc8::testability::Header &req, const std::uint8_t * /*dat*/,
                            std::size_t /*dat_len*/, const tc8::net::Endpoint & /*peer*/,
                            std::uint8_t &rid_out, std::vector<std::uint8_t> & /*resp_dat*/) {
    // An unknown PID under an owned GID is E_NTF by the MiddlewareModule
    // contract. This is the one dispatch the machine does not express, because
    // the SCXML has no vocabulary for a PID it was never told about.
    if (tc8::testability::pidOf(req.method_id) != kPidPing) {
        rid_out = tc8::testability::kRidENtf;
        return;
    }

    sm_.processEvent(gen::Event::Ping);

    // Projection, not a decision: exactly one state means the primitive was
    // accepted, and the SCXML is what decides which state the event lands in.
    rid_out = (sm_.getCurrentState() == gen::State::Answered) ? tc8::testability::kRidEOk
                                                             : tc8::testability::kRidENtf;
}

}  // namespace tc8::scxml_module
