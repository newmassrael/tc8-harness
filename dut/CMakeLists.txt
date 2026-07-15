# Two layers live under dut/, and they must not be confused:
#
#   1. The vendor-neutral AUTOSAR Testability UTM — dut_service's testability +
#      Upper Tester libraries and the standalone tc8-utm executable. This is what
#      the tc8-utm SDK exports. It has no vsomeip / CommonAPI / ETS dependency
#      (each of those targets says so in its own comment), so it builds ALWAYS.
#   2. The ETS mock DUT — dut/ets plus the tc8-dut executable. Built on vsomeip +
#      CommonAPI, and its code generators are a heavyweight extra toolchain, so it
#      stays behind TC8_BUILD_MOCK_DUT.
#
# Layer 1 used to sit behind layer 2's option and behind the REQUIRED
# commonapi-*-generator probes below, which inverted the dependency: a flag and a
# toolchain about the vsomeip mock DUT decided whether the vendor-neutral SDK
# existed at all. The visible cost was that the hosted build-test CI job configures
# with -DTC8_BUILD_MOCK_DUT=OFF, so the whole TC8_UTM_INSTALL block (guarded on
# TARGET tc8_testability_server) was skipped and utm_export_smoke never registered
# there — the SDK's own gate ran on exactly one self-hosted runner. Splitting the
# layers is what lets the SDK and its gate stand on their own.
#
# The generator probes are scoped to the ETS branch for the same reason: they are
# layer 2's toolchain, and a REQUIRED probe at this file's top level would fail a
# configure that only wants layer 1.
if(TC8_BUILD_MOCK_DUT)
    find_program(COMMONAPI_CORE_GEN   commonapi-core-generator   REQUIRED)
    find_program(COMMONAPI_SOMEIP_GEN commonapi-someip-generator REQUIRED)
    add_subdirectory(ets)
endif()

# Layer 1. dut_service defines the vendor-neutral libraries unconditionally and
# gates only tc8-dut (which links the ets targets above) on TC8_BUILD_MOCK_DUT.
add_subdirectory(dut_service)
add_subdirectory(utm)
