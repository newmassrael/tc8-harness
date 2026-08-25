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
    ${PROJECT_SOURCE_DIR}/src/cli/commands/sd_probe_command.cpp
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

    # `case_header` is the absolute path used to CHECK the header exists;
    # `case_include` is what the generated stub actually #includes, and the two
    # differ on purpose.
    #
    # For the in-tree traits header the include is written RELATIVE to
    # src/sce_integration/include (already on this target's include path), never
    # absolute. A stub is a GENERATED source, so an absolute path makes its
    # CONTENT depend on where the checkout happens to sit — and a ccache
    # direct-mode hit is keyed on exactly that content. Two checkouts of the same
    # commit (a developer's tree and the CI runner's workspace) then share no
    # cache entries at all, and the 750+ heavy case TUs recompile cold in
    # whichever one did not build last. Measured 2026-08-24: that is what put the
    # smoke lane's build past its 120-minute cap twice running, with every case
    # step still `pending` when the job was killed.
    #
    # A case-local traits header keeps the absolute form. It may live anywhere
    # (SITE_EXTRA_CASE_ROOTS points outside the tree), so there is no anchor on
    # the include path to make it relative to; adding each case dir to the include
    # path instead would let two suites' same-named headers resolve by search
    # order, which is the ODR hazard this file exists to avoid. Measured on the
    # in-tree suite: 752 of 752 stubs take the relative branch and none take this
    # one, so the cache-sharing win is complete without touching that risk.
    set(case_header ${case_dir}/${case_id}.h)
    set(case_include "${case_header}")
    set(traits_kind "case-local")
    if(NOT EXISTS ${case_header})
        set(case_header
            ${PROJECT_SOURCE_DIR}/src/sce_integration/include/sce_integration/cases/${case_id}.h)
        set(case_include "sce_integration/cases/${case_id}.h")
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

    # This case's contribution to a registration TU. The suite defines bracket the
    # include and are UNDEFINED again after it, because several cases now share one
    # TU and TC8_CASE_SM_HEADER differs per case — a leaked define would silently
    # bind the next case in the chunk to the previous one's state machine.
    set(case_block "")
    foreach(_d IN LISTS suite_defines)
        string(APPEND case_block "${_d}")
    endforeach()
    string(APPEND case_block "#include \"${case_include}\"\n")
    if(NOT suite_defines STREQUAL "")
        string(APPEND case_block
            "#undef TC8_CASE_SUITE\n"
            "#undef TC8_CASE_SUITE_NS\n"
            "#undef TC8_CASE_SM_HEADER\n")
    endif()

    # Bucket by a HASH of the case id, not by position in a sorted list. Both give
    # deterministic chunks, but a positional split shifts every case after an
    # insertion, so adding one case would rewrite most chunks and recompile the
    # whole suite; hashing perturbs exactly one. The bucket COUNT is derived after
    # collection (see the emit step) and only changes when a suite crosses a size
    # boundary, which is the one time a full recompile is unavoidable anyway.
    # The default suite's name IS the empty string, which cannot be an element of a
    # CMake list — appending it to the suite roster silently appends nothing, and
    # the emit step below then finds no suites at all. Key every per-suite property
    # on a non-empty token instead; the empty name survives only where it belongs,
    # inside the case block's defines (where the default suite emits none).
    if(_suite STREQUAL "")
        set(_skey "__default")
    else()
        set(_skey "${_suite}")
    endif()
    string(MD5 _case_md5 "${case_id}")
    string(SUBSTRING "${_case_md5}" 0 6 _case_md5)
    set_property(GLOBAL PROPERTY TC8_CASEBLOCK_${_skey}_${case_id} "${case_block}")
    set_property(GLOBAL APPEND PROPERTY TC8_CASE_IDS_${_skey} "${case_id}")
    set_property(GLOBAL PROPERTY TC8_CASEHASH_${_skey}_${case_id} "${_case_md5}")
    set_property(GLOBAL APPEND PROPERTY TC8_CASE_SUITES "${_skey}")
    set_property(GLOBAL PROPERTY TC8_CASE_STUBDIR_${_skey} "${stub_dir}")
endfunction()

# How many cases one registration TU should carry.
#
# MEASURED on this suite (2026-08-24, Release, one representative TU): compiling a
# case stub costs ~6.6 s, of which only 0.35 s is preprocessing and 2.9 s is parse
# + semantic analysis — the remaining ~74% is CODE GENERATION, and almost all of it
# is the SHARED template machinery instantiated afresh in every TU and then thrown
# away by the linker as duplicates. Putting several cases in one TU collapses those
# duplicate instantiations, which is why this pays where a precompiled header would
# not (a PCH could only address the ≤26% parse share):
#
#     cases/TU       total        per case
#     1 (today)      6.6 s        6.6 s
#     8             11.4 s        1.42 s
#     32            35.9 s        1.12 s     <- flat minimum
#     64            99.5 s        1.55 s     <- superlinear past ~32
#
# 32 is the measured floor; 64 already costs more per case (and more peak memory)
# than 32. Below ~8 the fixed ~9 s of shared instantiation stops amortising.
set(TC8_CASES_PER_TU 32 CACHE STRING
    "Cases per generated registration TU (measured optimum 32; see src/harness/CMakeLists.txt)")

# Emit the registration TUs, one per (suite, bucket), after every collection pass
# has run. Returns them in TC8_CASE_STUBS in the caller's scope.
#
# Deferred to here rather than written per case because the bucket count depends on
# how many cases a suite ended up with, which is not known until the last pass has
# added its last case.
function(tc8_emit_case_registration_tus)
    get_property(_suites GLOBAL PROPERTY TC8_CASE_SUITES)
    if(NOT _suites)
        return()
    endif()
    list(REMOVE_DUPLICATES _suites)
    set(_stubs)
    foreach(_skey IN LISTS _suites)
        get_property(_ids GLOBAL PROPERTY TC8_CASE_IDS_${_skey})
        get_property(_dir GLOBAL PROPERTY TC8_CASE_STUBDIR_${_skey})
        list(LENGTH _ids _n)
        # ceil(n / cases-per-TU), never zero.
        math(EXPR _buckets "(${_n} + ${TC8_CASES_PER_TU} - 1) / ${TC8_CASES_PER_TU}")
        if(_buckets LESS 1)
            set(_buckets 1)
        endif()
        # Sorted so a chunk's CONTENT depends only on its membership, never on the
        # order the collection passes happened to visit directories in — otherwise
        # an override pass reordering two cases would rewrite the chunk and
        # recompile it for no semantic change.
        list(SORT _ids)
        # Accumulated in global properties rather than a CMake list of bodies: a
        # body is multi-line text, and a list whose elements are text is exactly
        # where CMake's separator and empty-element rules bite. APPEND_STRING has
        # neither problem.
        math(EXPR _last "${_buckets} - 1")
        foreach(_idx RANGE 0 ${_last})
            set_property(GLOBAL PROPERTY TC8_BUCKETBODY_${_skey}_${_idx} "")
        endforeach()
        foreach(_id IN LISTS _ids)
            get_property(_h GLOBAL PROPERTY TC8_CASEHASH_${_skey}_${_id})
            get_property(_b GLOBAL PROPERTY TC8_CASEBLOCK_${_skey}_${_id})
            math(EXPR _idx "0x${_h} % ${_buckets}")
            set_property(GLOBAL APPEND_STRING
                         PROPERTY TC8_BUCKETBODY_${_skey}_${_idx} "${_b}")
        endforeach()
        foreach(_idx RANGE 0 ${_last})
            get_property(_body GLOBAL PROPERTY TC8_BUCKETBODY_${_skey}_${_idx})
            if(_body STREQUAL "")
                continue()  # a hash bucket can come out empty; emit no TU for it
            endif()
            set(_path ${_dir}/register_${_idx}.cpp)
            set(_text
"// Auto-generated by CMake. Do not edit.
// Pulls the TC8_REGISTER_CASE inline registrar of several cases into the link.
// Several per TU on purpose: ~74% of a one-case TU's cost is code generation for
// the SHARED template machinery, re-instantiated in every TU and discarded by the
// linker — see TC8_CASES_PER_TU in src/harness/CMakeLists.txt for the measurement.
${_body}")
            set(_existing "")
            if(EXISTS ${_path})
                file(READ ${_path} _existing)
            endif()
            if(NOT "${_existing}" STREQUAL "${_text}")
                file(WRITE ${_path} "${_text}")
            endif()
            list(APPEND _stubs ${_path})
        endforeach()
    endforeach()
    set(TC8_CASE_STUBS ${_stubs} PARENT_SCOPE)
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

# Every pass has contributed; now group the cases into registration TUs. Must come
# after the LAST tc8_add_case — a chunk's membership is not knowable before then.
#
# The per-case `<case_id>_register.cpp` files an older configure of this build dir
# left behind are removed first. They are not compiled (only what this function
# returns reaches target_sources), but a stale one still resolves against the tree
# and reads like a live source to anything that globs the directory — which is how
# a deleted case's stub, and its long-since-moved traits path, surfaced during this
# change.
file(GLOB _tc8_stale_stubs
     ${TC8_CASE_STUBS_DIR}/*_register.cpp
     ${TC8_CASE_STUBS_DIR}/*/*_register.cpp)
foreach(_s IN LISTS _tc8_stale_stubs)
    get_filename_component(_sn ${_s} NAME)
    if(NOT _sn MATCHES "^register_[0-9]+\\.cpp$")
        file(REMOVE ${_s})
    endif()
endforeach()

tc8_emit_case_registration_tus()
list(LENGTH TC8_CASE_STUBS _tc8_tu_count)
message(STATUS
    "TC8: ${_tc8_tu_count} case-registration TU(s) for the collected cases "
    "(TC8_CASES_PER_TU=${TC8_CASES_PER_TU})")
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

