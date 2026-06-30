// Strict-set compile witness for the first-party netlink headers
// (src/net/link_control.h and the src/net/rtnetlink.h SSOT it pulls in).
//
// Both headers ARE compiled in this tree today — by the DUT PosixSocketBackend
// (dut/dut_service/posix_socket_backend.cpp) and by link_control_test.cpp — but
// neither path is built under tc8_enable_strict_warnings (the dut/ targets and
// tc8_add_unit_test both omit it). So a glibc system-macro leaking a C-style cast
// into a first-party header (e.g. NLMSG_DATA tripping -Wold-style-cast) does NOT
// surface here; it surfaces only when a STRICT first-party consumer — an OEM
// conformance case that includes net/link_control.h — hits the gate.
//
// This translation unit exists ONLY to force that compile under the strict gate,
// so "the net headers pass the harness's own first-party warning set" is
// build-enforced and cannot rot. It is an OBJECT target (compile, no link): the
// -Wold-style-cast check fires while parsing the inline bodies, which is all the
// guard needs. Referencing setLinkState ODR-uses the inline entry point and
// documents intent; the function is never called.
#include "net/link_control.h"

namespace tc8::net::detail {

bool netHeadersStrictCompileWitness(const std::string &ifname) {
    return setLinkState(ifname, true);
}

}  // namespace tc8::net::detail
