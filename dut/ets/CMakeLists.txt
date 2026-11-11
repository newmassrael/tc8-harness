# ETS interface library — CommonAPI Proxy/Stub generated from ets.fidl/.fdepl.

# OEM extend seam (O1): the public ETS interface is the in-tree ets.fidl/.fdepl
# by default, but an OEM points TC8_ETS_FIDL/TC8_ETS_FDEPL at its private
# superset (public surface + its NDA events/methods, same ServiceID) to
# extend the service WITHOUT forking tc8-harness. The `if(NOT DEFINED)` guard
# mirrors the TC8_*_CASE_DIRS hardening (commit 46981678): under CMP0126 OLD
# (cmake 3.16) an unconditional set() would wipe a superproject's plain set().
# See docs/ets_dut_extension_seams.md.
if(NOT DEFINED TC8_ETS_FIDL)
    set(TC8_ETS_FIDL  "${CMAKE_CURRENT_SOURCE_DIR}/ets.fidl")
endif()
if(NOT DEFINED TC8_ETS_FDEPL)
    set(TC8_ETS_FDEPL "${CMAKE_CURRENT_SOURCE_DIR}/ets.fdepl")
endif()
foreach(_f TC8_ETS_FIDL TC8_ETS_FDEPL)
    if(NOT EXISTS "${${_f}}")
        message(FATAL_ERROR "${_f} points at a missing file: ${${_f}}")
    endif()
endforeach()

# Eventgroup membership seam: TC8_ETS_EVENTGROUPS is a list of
# `<event-id>=<eventgroup>[,<eventgroup>...]` entries, e.g.
# "0x8001=0x0002,0x0005;0x800B=0x0006". Each replaces the eventgroups the selected
# fdepl gives that event (a broadcast's SomeIpEventID or an attribute's
# SomeIpNotifierID), so a consumer can match its reference DUT's membership
# without copying the whole deployment. tools/ets_eventgroup_overlay.py writes the
# overlaid copy into this build tree and the codegen below reads it; the source
# fdepl is never touched. Empty (the default) generates from the fdepl as it is.
# It has to be a build-time choice: vsomeip adds eventgroups to an event already
# registered but never removes one. See docs/ets_dut_extension_seams.md.
if(NOT DEFINED TC8_ETS_EVENTGROUPS)
    set(TC8_ETS_EVENTGROUPS "")
endif()
set(TC8_ETS_FDEPL_EFFECTIVE "${TC8_ETS_FDEPL}")
if(TC8_ETS_EVENTGROUPS)
    if(NOT TC8_PYTHON3)
        message(FATAL_ERROR "TC8_ETS_EVENTGROUPS is set but no python3 was found to apply it")
    endif()
    get_filename_component(_tc8_fdepl_name "${TC8_ETS_FDEPL}" NAME)
    set(TC8_ETS_FDEPL_EFFECTIVE "${CMAKE_CURRENT_BINARY_DIR}/eventgroups/${_tc8_fdepl_name}")
    set(_tc8_overlay_tool "${CMAKE_CURRENT_LIST_DIR}/../../tools/ets_eventgroup_overlay.py")
    set(_tc8_overlay_args "")
    foreach(_tc8_override IN LISTS TC8_ETS_EVENTGROUPS)
        list(APPEND _tc8_overlay_args --override "${_tc8_override}")
    endforeach()
    add_custom_command(
        OUTPUT ${TC8_ETS_FDEPL_EFFECTIVE}
        COMMAND ${TC8_PYTHON3} ${_tc8_overlay_tool}
                --in ${TC8_ETS_FDEPL} --out ${TC8_ETS_FDEPL_EFFECTIVE} ${_tc8_overlay_args}
        DEPENDS ${TC8_ETS_FDEPL} ${_tc8_overlay_tool}
        COMMENT "ETS eventgroup overlay (${TC8_ETS_EVENTGROUPS})"
        VERBATIM
    )
    message(STATUS "TC8: ETS eventgroup overlay: ${TC8_ETS_EVENTGROUPS}")
endif()

set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(GEN_SUBDIR ${GEN_DIR}/v1/org/tc8/ets)

set(CORE_GENERATED
    ${GEN_SUBDIR}/EnhancedTestability.hpp
    ${GEN_SUBDIR}/EnhancedTestabilityProxy.hpp
    ${GEN_SUBDIR}/EnhancedTestabilityProxyBase.hpp
    ${GEN_SUBDIR}/EnhancedTestabilityStub.hpp
    ${GEN_SUBDIR}/EnhancedTestabilityStubDefault.hpp
)

set(SOMEIP_GENERATED
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPDeployment.hpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPDeployment.cpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPProxy.hpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPProxy.cpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPStubAdapter.hpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPStubAdapter.cpp
)

add_custom_command(
    OUTPUT ${CORE_GENERATED}
    COMMAND ${COMMONAPI_CORE_GEN} -d ${GEN_DIR} -sk Default
            ${TC8_ETS_FIDL}
    DEPENDS ${TC8_ETS_FIDL}
    COMMENT "CommonAPI core codegen (${TC8_ETS_FIDL})"
    VERBATIM
)

add_custom_command(
    OUTPUT ${SOMEIP_GENERATED}
    COMMAND ${COMMONAPI_SOMEIP_GEN} -d ${GEN_DIR}
            ${TC8_ETS_FDEPL_EFFECTIVE}
    DEPENDS ${TC8_ETS_FDEPL_EFFECTIVE} ${TC8_ETS_FIDL} ${CORE_GENERATED}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "CommonAPI SOME/IP codegen (${TC8_ETS_FDEPL_EFFECTIVE})"
    VERBATIM
)

add_library(ets OBJECT
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPDeployment.cpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPProxy.cpp
    ${GEN_SUBDIR}/EnhancedTestabilitySomeIPStubAdapter.cpp
)
target_include_directories(ets SYSTEM PUBLIC ${GEN_DIR})
target_link_libraries(ets PUBLIC CommonAPI CommonAPI-SomeIP vsomeip3)

# §5.1.5 multi-service axis: SERVICE-ID-2 lives in ets2.fidl/.fdepl
# (org.tc8.ets2.EnhancedTestability2). Only registered at runtime when
# TC8_DUT_SERVICE_2=1, paired with vsomeip-multi-service.json. Codegen
# lands under v1/org/tc8/ets2/.
set(GEN_SUBDIR2 ${GEN_DIR}/v1/org/tc8/ets2)

set(CORE_GENERATED2
    ${GEN_SUBDIR2}/EnhancedTestability2.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2Proxy.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2ProxyBase.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2Stub.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2StubDefault.hpp
)

set(SOMEIP_GENERATED2
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPDeployment.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPDeployment.cpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPProxy.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPProxy.cpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPStubAdapter.hpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPStubAdapter.cpp
)

add_custom_command(
    OUTPUT ${CORE_GENERATED2}
    COMMAND ${COMMONAPI_CORE_GEN} -d ${GEN_DIR} -sk Default
            ${CMAKE_CURRENT_SOURCE_DIR}/ets2.fidl
    DEPENDS ets2.fidl
    COMMENT "CommonAPI core codegen (ets2.fidl)"
    VERBATIM
)

add_custom_command(
    OUTPUT ${SOMEIP_GENERATED2}
    COMMAND ${COMMONAPI_SOMEIP_GEN} -d ${GEN_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/ets2.fdepl
    DEPENDS ets2.fdepl ets2.fidl ${CORE_GENERATED2}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "CommonAPI SOME/IP codegen (ets2.fdepl)"
    VERBATIM
)

add_library(ets2 OBJECT
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPDeployment.cpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPProxy.cpp
    ${GEN_SUBDIR2}/EnhancedTestability2SomeIPStubAdapter.cpp
)
target_include_directories(ets2 SYSTEM PUBLIC ${GEN_DIR})
target_link_libraries(ets2 PUBLIC CommonAPI CommonAPI-SomeIP vsomeip3)

# §5.1.6 SOMEIP_ETS_097 — ets3 is the tester-side target the DUT-as-client
# proxy subscribes to. Codegen lands under v1/org/tc8/ets3/. Only the
# Proxy-side artefacts are linked into tc8-dut (the DUT acts as client for
# this service); the StubAdapter is generated but unused.
set(GEN_SUBDIR3 ${GEN_DIR}/v1/org/tc8/ets3)

set(CORE_GENERATED3
    ${GEN_SUBDIR3}/ClientTarget.hpp
    ${GEN_SUBDIR3}/ClientTargetProxy.hpp
    ${GEN_SUBDIR3}/ClientTargetProxyBase.hpp
    ${GEN_SUBDIR3}/ClientTargetStub.hpp
    ${GEN_SUBDIR3}/ClientTargetStubDefault.hpp
)

set(SOMEIP_GENERATED3
    ${GEN_SUBDIR3}/ClientTargetSomeIPDeployment.hpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPDeployment.cpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPProxy.hpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPProxy.cpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPStubAdapter.hpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPStubAdapter.cpp
)

add_custom_command(
    OUTPUT ${CORE_GENERATED3}
    COMMAND ${COMMONAPI_CORE_GEN} -d ${GEN_DIR} -sk Default
            ${CMAKE_CURRENT_SOURCE_DIR}/ets3.fidl
    DEPENDS ets3.fidl
    COMMENT "CommonAPI core codegen (ets3.fidl)"
    VERBATIM
)

add_custom_command(
    OUTPUT ${SOMEIP_GENERATED3}
    COMMAND ${COMMONAPI_SOMEIP_GEN} -d ${GEN_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/ets3.fdepl
    DEPENDS ets3.fdepl ets3.fidl ${CORE_GENERATED3}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "CommonAPI SOME/IP codegen (ets3.fdepl)"
    VERBATIM
)

add_library(ets3 OBJECT
    ${GEN_SUBDIR3}/ClientTargetSomeIPDeployment.cpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPProxy.cpp
    ${GEN_SUBDIR3}/ClientTargetSomeIPStubAdapter.cpp
)
target_include_directories(ets3 SYSTEM PUBLIC ${GEN_DIR})
target_link_libraries(ets3 PUBLIC CommonAPI CommonAPI-SomeIP vsomeip3)
