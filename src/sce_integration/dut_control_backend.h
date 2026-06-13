#pragma once

namespace tc8::sce {

// Which DUT-control backend the harness drives a case's stimulus through.
//
//   kOpcode      — the in-house opcode Upper Tester (port 30600). The
//                  TC8-tailored superset every in-tree case has always used;
//                  the default so the whole suite is unaffected.
//   kTestability — the standard AUTOSAR Testability Protocol endpoint (port
//                  30700). The OEM-portable subset: a case routed over the
//                  Tier-2 seam runs against any standard DUT with config only.
//
// Selected by `--dut-control` and carried in TestConfig; consumed by
// `makeDutControl` (dut_control_factory.h). A backend that lacks a sub-interface
// a case needs returns nullptr from the accessor, and the case conditioning-
// skips rather than failing (see DutCapability in dut_control.h).
enum class DutControlBackend {
    kOpcode,
    kTestability,
};

}  // namespace tc8::sce
