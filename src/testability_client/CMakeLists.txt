# The tester-side AUTOSAR Testability Protocol client — the standard counterpart
# to the DUT-side endpoint in dut/dut_service (tc8_testability_core + a backend).
# Both halves frame against the one codec SSOT, include/tc8/testability_protocol.h,
# so they decode identically; this archive adds the tester's socket round trip and
# the standard typed primitives.
#
# A library for the same reason tc8_wire is one: the harness, the cross-compile
# portability check and the unit tests all drive this client, and naming the source
# by path in each list is what invites a second, drifting copy. It is also what the
# UTM SDK exports — a consumer that attaches an OEM service-group module to the
# endpoint links THIS to exercise it, so the exported surface carries both halves
# of the protocol rather than the endpoint alone.
#
# Dependency-light and vendor-neutral by construction: POSIX sockets plus the
# header-only codec — no threads, no libpcap/libtins/vsomeip — so it cross-compiles
# and an out-of-tree consumer inherits nothing but the seam. The install/EXPORT
# interface is wired once in the top-level TC8_UTM_INSTALL block.
add_library(tc8_testability_client STATIC
    testability_client.cpp
)
# The client's public header (include/tc8/testability_client.h) and the codec SSOT
# it frames against (tc8/testability_protocol.h) both live under include/tc8/, and
# the .cpp compiles against only those — so include/ is the sole PUBLIC include
# root, which the export block collapses onto the single install-tree include root.
target_include_directories(tc8_testability_client PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)
tc8_enable_strict_warnings(tc8_testability_client)
