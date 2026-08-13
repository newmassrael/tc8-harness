# ── Tester executable (tc8-harness) + per-case SCE state machines ─────────────
# The SOME/IP wire runner and its case machinery, built as the tester component.
# None of it is reachable from the exported SDK; the whole subdir is added only
# under TC8_BUILD_HARNESS. This dir also holds the tester's own translation units
# (harness_main / packet_pipeline / dut_control_factory); the shared libraries it
# links come from the sibling component dirs. Paths that reach the project root
# (tests/, src/sce_integration/, include/, the gen dir) are named by
# ${PROJECT_SOURCE_DIR} / ${PROJECT_BINARY_DIR} so they resolve from this subdir
# exactly as they did at the top level — the gen dir stays ${PROJECT_BINARY_DIR}/gen.


# The tester-side ArpResponder owns a std::thread worker; link Threads
# explicitly rather than relying on a transitive vsomeip pull-in. Only the tester
# needs it at this scope — dut_service and unit_tests each find their own.
find_package(Threads REQUIRED)

# The stateless wire builders + SOME/IP dissectors come from tc8_stimulus, and the
# capture / CLI-helper / case-registry / responder core from tc8_harness_core (both
# linked below). Listed here are the tester's own edges: the entry point, the
# pcap/vsomeip-driving CLI commands, the packet pipeline, and the DUT control factory.
add_executable(tc8-harness
    harness_main.cpp
    packet_pipeline.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/signal_handler.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/capture_driver.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/decode_pcap_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/live_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/replay_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/test_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/ut_ping_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_probe_command.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_send_command.cpp
    dut_control_factory.cpp
)

# The executable stays at the top-level build dir (${PROJECT_BINARY_DIR}/tc8-harness),
# NOT this component's build/src/harness/ subdir. It is invoked BY PATH as
# ./build/tc8-harness by the CI gates (build-test spec-coverage, smoke, pcap-refresh),
# the orchestrator (dut/env/orchestrator config default), setup-netns.sh, lib-sp-check.sh,
# and check-suite-producer.sh — moving it under the component dir broke all of them
# (exit 127). Pinning RUNTIME_OUTPUT_DIRECTORY restores the canonical path from the subdir.
set_target_properties(tc8-harness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# Each TC8 case lives in tests/<case_id>/ with its SCXML. The matching
# src/sce_integration/include/sce_integration/cases/<case_id>.h carries the TestCaseTraits
# specialization and a TC8_REGISTER_CASE() inline registrar. CMake generates
# a thin translation unit per case that includes the header, forcing the
# registrar to be pulled into the final link — so adding a case is just
# tests/<id>/<id>.scxml + src/sce_integration/include/sce_integration/cases/<id>.h.
#
# Out-of-tree extension points, for consumers embedding tc8-harness via
# FetchContent/add_subdirectory without forking it:
#
#   TC8_EXTRA_CASE_DIRS    — ;-separated directories, each containing case
#                            subdirectories shaped like tests/<case_id>/.
#                            A subdirectory whose name collides with an
#                            in-tree case is a configure error — replacing
#                            a case must be explicit (see below).
#   TC8_CASE_OVERRIDE_DIRS — ;-separated directories whose case
#                            subdirectories REPLACE the in-tree
#                            tests/<case_id>/ of the same name at collection
#                            time. A subdirectory that does not match any
#                            in-tree case is a configure error (typo guard).
#
# Traits header resolution for every collected case: <case_dir>/<case_id>.h
# first, then src/sce_integration/include/sce_integration/cases/<case_id>.h. An override that ships
# only the .scxml therefore reuses the in-tree traits (SCXML-level
# override); shipping <case_id>.h alongside replaces the whole case. New
# out-of-tree cases must carry their own traits header.
#
# Replacement happens before codegen, so exactly one state machine per case
# id reaches the link — the CaseRegistry duplicate-id abort stays a
# backstop, never the mechanism.
# Guarded cache declarations: under CMP0126 OLD (cmake_minimum_required
# 3.16) an unguarded `set(... CACHE ...)` erases a same-name normal
# variable inherited from a consumer superproject's scope — silently
# dropping the consumer's plain `set(TC8_EXTRA_CASE_DIRS ...)`. The
# guard keeps both spellings working: -D cache entries and plain set()
# before add_subdirectory/FetchContent_MakeAvailable.
if(NOT DEFINED TC8_EXTRA_CASE_DIRS)
    set(TC8_EXTRA_CASE_DIRS "" CACHE STRING
        "Directories containing additional out-of-tree case subdirectories")
endif()
if(NOT DEFINED TC8_CASE_OVERRIDE_DIRS)
    set(TC8_CASE_OVERRIDE_DIRS "" CACHE STRING
        "Directories whose case subdirectories replace in-tree tests/<id>/")
endif()
#   TC8_EXTRA_CASE_SUITES  — ;-separated suite names, one per TC8_EXTRA_CASE_DIRS
#                            root (index-aligned). A root's cases register under
#                            that suite; identity becomes (suite, case_id), so a
#                            non-default suite may reuse an in-tree case id. An
#                            empty or missing entry defaults to the in-tree
#                            suite "tc8" (kDefaultSuite).
if(NOT DEFINED TC8_EXTRA_CASE_SUITES)
    set(TC8_EXTRA_CASE_SUITES "" CACHE STRING
        "Suite name per TC8_EXTRA_CASE_DIRS root (;-aligned); empty/missing => default")
endif()

#   TC8_EXTRA_CASE_LIBS    — ;-separated link libraries added to tc8-harness, for
#                            out-of-tree cases whose code needs something the base
#                            tester does not link. The tester-side counterpart of
#                            the DUT's TC8_ETS_EXTENSION_LIBS, and the supported
#                            way to reach a SOME/IP middleware stack from a case:
#                            the tester itself does not link one (see the
#                            target_link_libraries comment below), so a consumer
#                            that wants vsomeip in its own case names it here
#                            rather than relying on it being incidentally present.
if(NOT DEFINED TC8_EXTRA_CASE_LIBS)
    set(TC8_EXTRA_CASE_LIBS "" CACHE STRING
        "Additional link libraries for tc8-harness (out-of-tree case dependencies)")
endif()

# The in-tree default suite name has its single source of truth in the C++
# constant kDefaultSuite (src/sce_integration/include/sce_integration/case_registry.h). Derive it here
# rather than restating the literal, so the configure-time suite logic and the
# runtime registry can never disagree on the default suite's name.
file(STRINGS ${PROJECT_SOURCE_DIR}/src/sce_integration/include/sce_integration/case_registry.h _tc8_kdefault_line
     REGEX "kDefaultSuite[ \t]*=[ \t]*\"[^\"]+\"")
if(NOT _tc8_kdefault_line)
    message(FATAL_ERROR
        "TC8: could not derive the default suite name from kDefaultSuite in "
        "src/sce_integration/include/sce_integration/case_registry.h — update the SSOT-extraction regex")
endif()
string(REGEX REPLACE ".*\"([^\"]+)\".*" "\\1" TC8_DEFAULT_SUITE "${_tc8_kdefault_line}")

# gen/ holds the registration stubs and the per-suite codegen output, and its
# root is on the tc8-harness include path so a non-default suite's generated SM
# header resolves via its suite-qualified path "<suite>/<case_id>_sm.h" (stamped
# by tc8_add_case). The in-tree "<case_id>_sm.h" lives in the default
# "generated/" dir; SCE (SCECodegen.cmake) also adds each per-suite
# "gen/<suite>/" dir to the include path, so an in-tree bare include is
# disambiguated by SEARCH ORDER: Pass 2 (in-tree -> "generated/") is collected
# before Pass 3 (extra suites), so "generated/" precedes any "gen/<suite>/" and
# the in-tree case binds its own header. That pass ordering IS the isolation
# invariant — do not reorder the passes.
set(TC8_CASE_GEN_DIR ${PROJECT_BINARY_DIR}/gen)
set(TC8_CASE_STUBS_DIR ${TC8_CASE_GEN_DIR}/cases_stubs)
file(MAKE_DIRECTORY ${TC8_CASE_STUBS_DIR})
set(TC8_CASE_STUBS)

# Fail loud at configure time if the resolved sce-codegen accepts but does NOT
# honour --cpp-namespace-prefix (some builds parse the flag yet emit un-nested
# headers — verified to happen). Without nesting, a non-default suite's SM type
# equals the in-tree type and the two collide silently (ODR / one-definition-
# wins) the moment they share a case id. Probes once per configure, only when a
# non-default suite is actually requested, so the default build pays nothing.
function(tc8_assert_codegen_nests)
    get_property(_done GLOBAL PROPERTY _TC8_CODEGEN_NEST_CHECKED)
    if(_done)
        return()
    endif()
    set_property(GLOBAL PROPERTY _TC8_CODEGEN_NEST_CHECKED 1)
    set(_probe ${TC8_CASE_GEN_DIR}/_codegen_probe)
    file(MAKE_DIRECTORY ${_probe})
    file(WRITE ${_probe}/tc8_probe.scxml
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<scxml xmlns=\"http://www.w3.org/2005/07/scxml\" version=\"1.0\" "
        "name=\"tc8_probe\" datamodel=\"null\" initial=\"s0\">\n"
        "  <state id=\"s0\"><transition target=\"s1\"/></state>\n"
        "  <final id=\"s1\"/>\n</scxml>\n")
    set(_probe_cmd ${SCE_CODEGEN} generate ${_probe}/tc8_probe.scxml
                   -o ${_probe} -l cpp --cpp-namespace-prefix __tc8_probe)
    if(SCE_TEMPLATE_DIR)
        set(_probe_cmd ${CMAKE_COMMAND} -E env
            "SCE_TEMPLATE_DIR=${SCE_TEMPLATE_DIR}" ${_probe_cmd})
    endif()
    execute_process(COMMAND ${_probe_cmd}
        RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_QUIET)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR
            "TC8: sce-codegen probe failed (rc=${_rc}) using ${SCE_CODEGEN}")
    endif()
    file(STRINGS ${_probe}/tc8_probe_sm.h _ns
         REGEX "namespace SCE::Generated::__tc8_probe")
    if(NOT _ns)
        message(FATAL_ERROR
            "TC8: sce-codegen (${SCE_CODEGEN}) accepts but does not honour "
            "--cpp-namespace-prefix — the probe header is not nested under "
            "::SCE::Generated::__tc8_probe. A non-default case suite needs a "
            "codegen that nests, else two suites sharing a case id collide "
            "(ODR). Update sce-codegen (>= the pinned third_party/sce VERSION).")
    endif()
endfunction()

# Registers one case directory: SCXML codegen + traits-header resolution +
# registration-stub TU. Appends the stub to TC8_CASE_STUBS in the caller's
# scope. `origin` is "in-tree", "override", or "extra" — out-of-tree
# origins are logged per case (the in-tree bulk is already covered by the
# per-machine SCE codegen lines). `suite` is the catalog name (empty or the
# default-suite name => the in-tree default; any other => a nested OEM suite).
function(tc8_add_case case_dir origin suite)
    get_filename_component(case_id ${case_dir} NAME)

    # Suite identity matches the registry's, which is case-insensitive: normalise
    # to lower case so a root declared "VENDORX" and the registry's "vendorx" never
    # diverge across the configure/runtime boundary. Empty or the default-suite
    # name selects the in-tree default.
    string(TOLOWER "${suite}" _suite)

    # Default suite: byte-identical to the pre-suite build. The SM generates as
    # ::SCE::Generated::<name> into the shared "generated/" dir and the stub
    # carries no suite define, so the ~750 in-tree cases are untouched.
    if(_suite STREQUAL "" OR _suite STREQUAL "${TC8_DEFAULT_SUITE}")
        sce_add_state_machines_from_dir(
            TARGET    tc8-harness
            SCXML_DIR ${case_dir})
        set(stub_dir ${TC8_CASE_STUBS_DIR})
        set(suite_defines "")
    else()
        # The suite name becomes a C++ namespace token, a path segment, and a
        # registry string — reject anything that is not a plain C++ identifier so
        # a bad name fails fast here instead of as a cryptic codegen/compile error
        # downstream.
        if(NOT _suite MATCHES "^[a-z_][a-z0-9_]*$")
            message(FATAL_ERROR
                "TC8: suite name '${suite}' is not a valid C++ identifier "
                "([A-Za-z_][A-Za-z0-9_]*) — it nests the generated namespace "
                "::SCE::Generated::<suite>::")
        endif()
        # Guard the ODR-distinctness invariant: a codegen that ignored the prefix
        # would silently un-nest this suite onto the in-tree type.
        tc8_assert_codegen_nests()
        # A non-default suite nests the SM under ::SCE::Generated::<suite>::<name>
        # in a per-suite output dir (so identical case ids never share a generated
        # file) and the stub stamps three tokens the OEM case header binds against:
        # TC8_CASE_SUITE (registry identity string), TC8_CASE_SUITE_NS (C++
        # namespace token), TC8_CASE_SM_HEADER (the suite-qualified header path).
        # Distinct suite => distinct namespace => distinct SM type => the
        # gRegisterCase<SM> ODR invariant in case_registry.h holds.
        sce_add_state_machines_from_dir(
            TARGET               tc8-harness
            SCXML_DIR            ${case_dir}
            OUTPUT_DIR           ${TC8_CASE_GEN_DIR}/${_suite}
            CPP_NAMESPACE_PREFIX ${_suite})
        set(stub_dir ${TC8_CASE_STUBS_DIR}/${_suite})
        file(MAKE_DIRECTORY ${stub_dir})
        set(suite_defines
            "#define TC8_CASE_SUITE \"${_suite}\"\n"
            "#define TC8_CASE_SUITE_NS ${_suite}\n"
            "#define TC8_CASE_SM_HEADER \"${_suite}/${case_id}_sm.h\"\n")
    endif()

    set(case_header ${case_dir}/${case_id}.h)
    set(traits_kind "case-local")
    if(NOT EXISTS ${case_header})
        set(case_header
            ${PROJECT_SOURCE_DIR}/src/sce_integration/include/sce_integration/cases/${case_id}.h)
        set(traits_kind "in-tree")
    endif()
    if(NOT EXISTS ${case_header})
        message(FATAL_ERROR
            "TC8: case '${case_id}' (${case_dir}): no traits header at "
            "${case_dir}/${case_id}.h or "
            "src/sce_integration/include/sce_integration/cases/${case_id}.h")
    endif()

    if(_suite STREQUAL "")
        set(_suite_disp "${TC8_DEFAULT_SUITE}")
    else()
        set(_suite_disp "${_suite}")
    endif()
    if(NOT origin STREQUAL "in-tree")
        message(STATUS
            "TC8: ${origin} case '${_suite_disp}:${case_id}' collected from "
            "${case_dir} (traits: ${traits_kind})")
    endif()

    set(stub_path    ${stub_dir}/${case_id}_register.cpp)
    set(stub_content
        "// Auto-generated by CMake. Do not edit.\n"
        "// Pulls the TC8_REGISTER_CASE inline registrar from the case's\n"
        "// traits header into the link.\n"
        ${suite_defines}
        "#include \"${case_header}\"\n")
    set(existing "")
    if(EXISTS ${stub_path})
        file(READ ${stub_path} existing)
    endif()
    string(JOIN "" stub_joined ${stub_content})
    if(NOT "${existing}" STREQUAL "${stub_joined}")
        file(WRITE ${stub_path} "${stub_joined}")
    endif()
    list(APPEND TC8_CASE_STUBS ${stub_path})
    set(TC8_CASE_STUBS ${TC8_CASE_STUBS} PARENT_SCOPE)
endfunction()

# Shared sanity checks for an out-of-tree injection root: a mistyped path
# or a flat .scxml layout would otherwise inject nothing, silently.
function(tc8_check_injection_root root_dir var_name)
    if(NOT IS_DIRECTORY ${root_dir})
        message(FATAL_ERROR
            "${var_name}: '${root_dir}' is not a directory — check the "
            "configured path")
    endif()
    file(GLOB _stray_scxml ${root_dir}/*.scxml)
    if(_stray_scxml)
        message(FATAL_ERROR
            "${var_name}: found .scxml file(s) directly under "
            "'${root_dir}' — cases must live in <root>/<case_id>/ "
            "subdirectories: ${_stray_scxml}")
    endif()
endfunction()

# Pass 1 — collect the override map: case id → replacement dir.
set(_tc8_override_ids "")
foreach(override_root ${TC8_CASE_OVERRIDE_DIRS})
    tc8_check_injection_root(${override_root} TC8_CASE_OVERRIDE_DIRS)
    set(_tc8_root_hits 0)
    file(GLOB _tc8_override_case_dirs LIST_DIRECTORIES true CONFIGURE_DEPENDS
         ${override_root}/*)
    foreach(case_dir ${_tc8_override_case_dirs})
        if(NOT IS_DIRECTORY ${case_dir})
            continue()
        endif()
        get_filename_component(case_id ${case_dir} NAME)
        if(case_id MATCHES "^_")
            message(STATUS
                "TC8: skipping auxiliary directory '${case_dir}' "
                "(leading underscore)")
            continue()
        endif()
        if(NOT IS_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/${case_id})
            message(FATAL_ERROR
                "TC8_CASE_OVERRIDE_DIRS: '${case_dir}' does not match any "
                "in-tree tests/${case_id}/ — overrides must replace an "
                "existing case; use TC8_EXTRA_CASE_DIRS for new cases")
        endif()
        if(case_id IN_LIST _tc8_override_ids)
            message(FATAL_ERROR
                "TC8_CASE_OVERRIDE_DIRS: case '${case_id}' overridden by "
                "more than one directory")
        endif()
        list(APPEND _tc8_override_ids ${case_id})
        set(_tc8_override_dir_${case_id} ${case_dir})
        math(EXPR _tc8_root_hits "${_tc8_root_hits} + 1")
    endforeach()
    if(_tc8_root_hits EQUAL 0)
        message(WARNING
            "TC8_CASE_OVERRIDE_DIRS: '${override_root}' contains no case "
            "subdirectories — nothing overridden from this root")
    endif()
endforeach()

# Pass 2 — in-tree cases; an overridden id is collected from its
# replacement dir instead. Leading-underscore directories (e.g.
# tests/_templates/) are auxiliary — sce:template fragments, shared
# fixtures — not TC8 cases. Skip them so they don't try to resolve a
# non-existent traits header.
set(_tc8_intree_count 0)
set(_tc8_overrides_applied 0)
file(GLOB TC8_CASE_DIRS LIST_DIRECTORIES true CONFIGURE_DEPENDS
     ${PROJECT_SOURCE_DIR}/tests/*)
foreach(case_dir ${TC8_CASE_DIRS})
    if(NOT IS_DIRECTORY ${case_dir})
        continue()
    endif()
    get_filename_component(case_id ${case_dir} NAME)
    if(case_id MATCHES "^_")
        message(STATUS
            "TC8: skipping auxiliary directory '${case_dir}' "
            "(leading underscore)")
        continue()
    endif()
    if(case_id IN_LIST _tc8_override_ids)
        tc8_add_case(${_tc8_override_dir_${case_id}} override "")
        math(EXPR _tc8_overrides_applied "${_tc8_overrides_applied} + 1")
    else()
        tc8_add_case(${case_dir} in-tree "")
        math(EXPR _tc8_intree_count "${_tc8_intree_count} + 1")
    endif()
endforeach()

# Every collected override id matched an in-tree case (pass 1 enforces
# it), so the applied count can only diverge from the map size if the
# in-tree glob and the existence check raced a concurrent tree edit —
# fail loudly rather than ship a partially-applied override set.
list(LENGTH _tc8_override_ids _tc8_overrides_requested)
if(NOT _tc8_overrides_applied EQUAL _tc8_overrides_requested)
    message(FATAL_ERROR
        "TC8: ${_tc8_overrides_requested} override(s) requested but "
        "${_tc8_overrides_applied} applied — tests/ changed during "
        "configure; re-run cmake")
endif()

# Pass 3 — out-of-tree additional cases. Each injection root carries a suite
# (TC8_EXTRA_CASE_SUITES, index-aligned with TC8_EXTRA_CASE_DIRS; an empty or
# missing entry, or the default-suite name, selects the in-tree default).
# Identity is (suite, case_id): a case id shared with an in-tree case is allowed
# ONLY under a non-default suite — that is the suite axis. A default-suite extra
# that shadows tests/<id>/ stays an error (replacing a case must be explicit via
# TC8_CASE_OVERRIDE_DIRS).
list(LENGTH TC8_EXTRA_CASE_DIRS _tc8_dir_count)
list(LENGTH TC8_EXTRA_CASE_SUITES _tc8_suite_count)
if(_tc8_suite_count GREATER _tc8_dir_count)
    message(FATAL_ERROR
        "TC8_EXTRA_CASE_SUITES has ${_tc8_suite_count} entries but "
        "TC8_EXTRA_CASE_DIRS has ${_tc8_dir_count} — the two lists are "
        "index-aligned; remove the surplus suite name(s)")
endif()
set(_tc8_extra_keys "")
set(_tc8_extra_root_index 0)
foreach(extra_root ${TC8_EXTRA_CASE_DIRS})
    tc8_check_injection_root(${extra_root} TC8_EXTRA_CASE_DIRS)
    if(_tc8_extra_root_index LESS _tc8_suite_count)
        list(GET TC8_EXTRA_CASE_SUITES ${_tc8_extra_root_index} _tc8_raw_suite)
    else()
        set(_tc8_raw_suite "")
    endif()
    # Normalise to the registry's case-insensitive identity; an empty entry or
    # the default name both resolve to the in-tree default suite.
    string(TOLOWER "${_tc8_raw_suite}" _tc8_root_suite)
    if(_tc8_root_suite STREQUAL "" OR _tc8_root_suite STREQUAL "${TC8_DEFAULT_SUITE}")
        set(_tc8_root_suite "${TC8_DEFAULT_SUITE}")
        set(_tc8_root_is_default TRUE)
    else()
        set(_tc8_root_is_default FALSE)
    endif()
    set(_tc8_root_hits 0)
    file(GLOB _tc8_extra_case_dirs LIST_DIRECTORIES true CONFIGURE_DEPENDS
         ${extra_root}/*)
    foreach(case_dir ${_tc8_extra_case_dirs})
        if(NOT IS_DIRECTORY ${case_dir})
            continue()
        endif()
        get_filename_component(case_id ${case_dir} NAME)
        if(case_id MATCHES "^_")
            message(STATUS
                "TC8: skipping auxiliary directory '${case_dir}' "
                "(leading underscore)")
            continue()
        endif()
        if(_tc8_root_is_default AND
           IS_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/${case_id})
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: '${case_dir}' collides with in-tree "
                "tests/${case_id}/ in the default suite — replace it via "
                "TC8_CASE_OVERRIDE_DIRS, or give this root a distinct suite "
                "name via TC8_EXTRA_CASE_SUITES")
        endif()
        set(_tc8_key "${_tc8_root_suite}:${case_id}")
        if(_tc8_key IN_LIST _tc8_extra_keys)
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: case '${_tc8_root_suite}:${case_id}' "
                "provided by more than one directory")
        endif()
        list(APPEND _tc8_extra_keys ${_tc8_key})
        tc8_add_case(${case_dir} extra "${_tc8_root_suite}")
        math(EXPR _tc8_root_hits "${_tc8_root_hits} + 1")
    endforeach()
    if(_tc8_root_hits EQUAL 0)
        message(WARNING
            "TC8_EXTRA_CASE_DIRS: '${extra_root}' contains no case "
            "subdirectories — nothing added from this root")
    endif()
    math(EXPR _tc8_extra_root_index "${_tc8_extra_root_index} + 1")
endforeach()

list(LENGTH _tc8_extra_keys _tc8_extra_count)
message(STATUS
    "TC8: case collection complete — ${_tc8_intree_count} in-tree, "
    "${_tc8_overrides_applied} overridden, ${_tc8_extra_count} "
    "out-of-tree extra")
target_sources(tc8-harness PRIVATE ${TC8_CASE_STUBS})
target_include_directories(tc8-harness PRIVATE
    # The tester's own CLI command headers (capture_driver/live/replay/test/…),
    # exposed under the cli/ prefix from their owning sub-dir. Private to the two
    # executables that compile the commands (this one and tc8-testability-send);
    # kept off tc8_harness_core's public surface so a dep-light test linking the
    # core cannot reach the tester's libpcap/CLI11 command headers.
    ${PROJECT_SOURCE_DIR}/src/cli/commands/include
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/third_party/CLI11
    ${TC8_CASE_GEN_DIR}
    ${PCAP_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
)
target_link_libraries(tc8-harness PRIVATE
    tc8_someiptp
    # tc8_e2e (AUTOSAR E2E Profile 5/11 checker engine) is linked so out-of-tree
    # cases injected via TC8_EXTRA_CASE_DIRS can resolve tc8::e2e::Profile*Checker
    # for E2E verdicts. No in-tree consumer references it, so the static archive
    # contributes no objects to the base binary (nothing to dead-strip differently).
    tc8_e2e
    # NOT linked here: vsomeip3 / CommonAPI / CommonAPI-SomeIP. The tester puts
    # crafted SOME/IP bytes on the wire and dissects what comes back; it does not
    # USE a SOME/IP middleware stack, and no source under src/ includes one. They
    # were on this line historically and resolved no symbol (readelf -d showed no
    # DT_NEEDED for any of the three), so the produced binary is unchanged — but
    # naming them here made the stack a REQUIRED configure-time dependency of the
    # tester, which is why a tester-only build had to install Boost, a source-built
    # vsomeip and two CommonAPI runtimes. The stack is the DUT's dependency and is
    # now found only under TC8_BUILD_MOCK_DUT (root CMakeLists.txt).
    #
    # An out-of-tree case that genuinely wants to call into a SOME/IP stack links
    # it explicitly via TC8_EXTRA_CASE_LIBS below — the tester-side counterpart of
    # the DUT's TC8_ETS_EXTENSION_LIBS.
    sce_base
    tc8_wire
    # The stateless wire builders + SOME/IP dissectors, shared with the portability
    # check and the unit tests. Carries tc8_wire / tc8_someiptp / Threads transitively.
    tc8_stimulus
    # The dependency-light harness core (capture, CLI helpers, case registry, socket
    # responders) shared with the unit tests. Carries tc8_stimulus transitively.
    tc8_harness_core
    # The tester-side testability client (testability-probe + the case-side
    # primitives). The same archive the UTM SDK exports, so the harness drives a
    # DUT through exactly the client an out-of-tree consumer gets.
    tc8_testability_client
    Threads::Threads
    ${PCAP_LIBRARY}
    ${LIBTINS_LIBRARY}
)
# Out-of-tree case dependencies (TC8_EXTRA_CASE_LIBS). Applied after the base set so
# a consumer's library can resolve against it; empty for every in-tree configure, so
# the default link line is unchanged.
if(TC8_EXTRA_CASE_LIBS)
    target_link_libraries(tc8-harness PRIVATE ${TC8_EXTRA_CASE_LIBS})
endif()
tc8_enable_strict_warnings(tc8-harness)

