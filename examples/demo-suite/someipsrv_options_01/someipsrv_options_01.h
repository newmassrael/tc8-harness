#pragma once

// Demo-suite traits header — the OEM-side authoring convention for a case in a
// non-default suite. It is byte-for-byte the same shape as an in-tree case
// EXCEPT it binds its state machine through the three tokens the per-suite
// register stub stamps (see tc8_add_case in CMakeLists.txt):
//
//   TC8_CASE_SM_HEADER  — the suite-qualified generated-header path
//                         ("demo/someipsrv_options_01_sm.h")
//   TC8_CASE_SUITE_NS   — the C++ namespace token (demo) under
//                         ::SCE::Generated:: that --cpp-namespace-prefix nested
//   TC8_CASE_SUITE      — the registry identity string ("demo"), consumed by
//                         CaseRegistrar via case_registry.h
//
// Because the suite name lives only in those macros, the same header text works
// under any suite. Reusing the in-tree id SOMEIPSRV_OPTIONS_01 here proves the
// (suite, id) identity keeps the two cases distinct at every layer.

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include TC8_CASE_SM_HEADER

namespace tc8::sce::cases {

using DemoOptions01SM =
    ::SCE::Generated::TC8_CASE_SUITE_NS::someipsrv_options_01::someipsrv_options_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::DemoOptions01SM>
    : SomeIpAnyBase<cases::DemoOptions01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_OPTIONS_01";
    static constexpr std::string_view kDescription =
        "Demo suite — proves (suite, id) coexistence with the in-tree case";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::DemoOptions01SM, demo_someipsrv_options_01)
