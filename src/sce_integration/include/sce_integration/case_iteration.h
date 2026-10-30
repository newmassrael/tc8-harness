#pragma once

#include "sce_integration/case_registry.h"

// A TC8 case that runs several iterations, declared as the ordered set of them.
//
// The TC8 case id names a question; the spec's procedure asks it in iterations (the
// same steps with a different flag, a different segment, a different phase). Each
// iteration is its own state machine with its own stimulus, registered as a case under
// "<id>_IT<n>" like any other (TC8_REGISTER_CASE), so it carries its own capabilities,
// its own capture window and its own verdict. The TC8 case is composed from them by
// CaseRegistry::composeIterations: running it runs each iteration as a case of its own
// and its verdict is their conjunction, so a `fail` in one never hides what another
// found, and the capability a single iteration needs gates that iteration alone when it
// is named (a consumer's alias line `iteration <n>`).
//
//   TC8_REGISTER_ITERATED_CASE("TCP_BASICS_04", "what the whole case asks, in our words")
//
// declares the case; its iterations register themselves. Everything else the case
// reports (topology, capture filter, capabilities) is read off the iterations, which must
// agree on the setup (CaseRegistry::composeIterations refuses a case whose iterations
// differ in topology, capture filter or control-plane role).

namespace tc8::sce {

struct IteratedCaseRegistrar {
    IteratedCaseRegistrar(std::string_view suite, std::string_view id,
                          std::string_view description) {
        CaseRegistry::instance().addIteratedCase(IteratedCaseDecl{suite, id, description});
    }
};

}  // namespace tc8::sce

#define TC8_ITERATED_CONCAT_INNER(a, b) a##b
#define TC8_ITERATED_CONCAT(a, b) TC8_ITERATED_CONCAT_INNER(a, b)
// Written without a trailing semicolon, like TC8_REGISTER_CASE.
#define TC8_REGISTER_ITERATED_CASE(id, description)                                   \
    static const ::tc8::sce::IteratedCaseRegistrar TC8_ITERATED_CONCAT(               \
        tc8_iterated_case_registrar_, __COUNTER__)(TC8_CASE_SUITE, id, description);
