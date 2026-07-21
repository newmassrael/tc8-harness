// Strict-set compile witness for tc8/net/link_control.h (the setLinkState
// link-loss fault injector) and the tc8/net/rtnetlink.h SSOT it pulls in.
//
// rtnetlink.h is now strict-compiled in PRODUCTION via tc8_posix_backend
// (posix_socket_backend.cpp includes it and that target is strict-gated). But
// link_control.h has NO production consumer — only link_control_test.cpp and
// netns_test_util.h include it, and unit-test TUs are not strict-gated — so a
// glibc-macro cast/conversion leaking into it would surface only when a STRICT
// first-party consumer (an OEM conformance case that includes net/link_control.h)
// hit the gate. This OBJECT target compiles it under the strict set so that
// contract is build-enforced and cannot rot. Compile, no link — the
// -Wold-style-cast / -Wsign-conversion checks fire while parsing the inline
// bodies, which is all the guard needs. Referencing setLinkState ODR-uses the
// inline entry point and documents intent; the function is never called.
#include "tc8/net/link_control.h"

namespace tc8::net::detail {

bool netHeadersStrictCompileWitness(const std::string &ifname) {
    return setLinkState(ifname, true);
}

}  // namespace tc8::net::detail
