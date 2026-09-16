# SCE pin integrity, checked at CONFIGURE time (requirement R5 of
# claudedocs/utm-module-from-scxml-requirements.md).
#
# What this checks and what it deliberately does not
# --------------------------------------------------
# R5 asks for "one pinned generator": a consumer pins an SCE revision and a
# mismatch fails at configure time with both revisions named. Only half of that
# is expressible against the revision this repository vendors, and the reason is
# worth writing down rather than faking:
#
#   * The generator may or may not report its own revision, and which it does is
#     a property of the BUILD, not of this repository. Upstream stamps the commit
#     into the CLI version string
#     (`concat!(CARGO_PKG_VERSION, " (", SCE_GIT_COMMIT, ")")`), so a new enough
#     `sce-codegen --version` prints `0.1.0 (<commit>)` and a revision comparison
#     becomes possible. A generator built before that stamp prints a bare
#     `0.1.0` and has no second revision to compare against.
#     So the comparison below is written once and arms itself: when the binary
#     answers, a mismatch against the pin is FATAL; when it stays silent, that
#     silence is reported rather than passed over, because a check that cannot
#     run is not the same as a check that passed.
#   * `template-hash` cannot stand in for it. The generator derives that hash
#     from a workspace root holding both the template tree and `Cargo.lock`, and
#     the vendored snapshot ships no `Cargo.lock` — so pointed at
#     third_party/sce it emits the all-zero fallback. Pointed anywhere else it
#     fingerprints a tree this repository does not pin.
#
# What IS checkable is checked below, and both are real failures that have
# happened in this class of build:
#
#   1. The snapshot's two records of its own pin agree. `VERSION` and
#      `MANIFEST.json`'s `embed_version` are written together by the vendoring
#      step, so a disagreement means a half-finished re-vendor. Upstream's own
#      embed tree carries exactly that defect today (its VERSION, its MANIFEST
#      and its HEAD name three different commits), which is what makes this
#      worth gating rather than assuming.
#   2. The resolved generator can actually render the vendored templates. A
#      generator older than the templates it is handed fails with an unknown
#      filter at RENDER time, i.e. midway through a build, with a message that
#      names neither side. Catching it here costs one codegen invocation and the
#      failure names the binary and the pin.
#
# This is distinct from `tc8_assert_codegen_nests()` in src/harness: that probe
# asserts a CAPABILITY (`--cpp-namespace-prefix` really nests) and runs only when
# a non-default case suite is requested. This one runs on every configure,
# because every configure that generates anything depends on it.

function(tc8_check_sce_pin)
    set(_vendor "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sce")

    # TC8_SCE_FIND_PACKAGE=ON consumes an installed SCE and vendors nothing, so
    # there is no snapshot to check. Silence rather than a warning: that
    # configuration opts out of the pin by construction.
    if(NOT EXISTS "${_vendor}/VERSION")
        return()
    endif()

    file(READ "${_vendor}/VERSION" _pin)
    string(STRIP "${_pin}" _pin)

    if(EXISTS "${_vendor}/MANIFEST.json")
        file(READ "${_vendor}/MANIFEST.json" _manifest)
        # string(JSON) needs CMake 3.19; this project's floor is 3.16.
        string(REGEX MATCH "\"embed_version\"[ \t]*:[ \t]*\"([^\"]*)\"" _matched "${_manifest}")
        set(_embed "${CMAKE_MATCH_1}")
        if(NOT _matched)
            message(FATAL_ERROR
                "TC8: third_party/sce/MANIFEST.json carries no embed_version — "
                "the vendored snapshot cannot state which SCE revision it is. "
                "third_party/sce/VERSION says '${_pin}'.")
        endif()
        if(NOT _pin STREQUAL _embed)
            message(FATAL_ERROR
                "TC8: the vendored SCE snapshot disagrees with itself about its "
                "own revision:\n"
                "  third_party/sce/VERSION              = ${_pin}\n"
                "  third_party/sce/MANIFEST.json        = ${_embed}\n"
                "Both are written by the same vendoring step, so this is a "
                "half-finished re-vendor. Re-run it rather than editing either "
                "file by hand.")
        endif()
    endif()

    # Nothing resolved a generator (SDK-only configure, or find_package supplied
    # the library but no CLI) — there is no renderer to probe.
    if(NOT SCE_CODEGEN)
        message(STATUS "TC8: SCE pin ${_pin} (no sce-codegen resolved; render probe skipped)")
        return()
    endif()

    # Revision comparison, armed but only firing when the generator can answer.
    execute_process(COMMAND "${SCE_CODEGEN}" --version
        RESULT_VARIABLE _ver_rc
        OUTPUT_VARIABLE _ver_out
        ERROR_VARIABLE _ver_err
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(_reported "")
    if(_ver_rc EQUAL 0)
        string(REGEX MATCH "\\(([0-9a-fA-F]+)\\)" _ver_matched "${_ver_out}")
        if(_ver_matched)
            set(_reported "${CMAKE_MATCH_1}")
        endif()
    endif()

    if(_reported)
        # The two sides are abbreviated to different widths — the vendored pin is
        # 9 hex, upstream stamps 12 — so compare on the shorter prefix instead of
        # demanding equal length, which would reject a correct pair.
        string(LENGTH "${_pin}" _pin_len)
        string(LENGTH "${_reported}" _rep_len)
        set(_n ${_pin_len})
        if(_rep_len LESS _n)
            set(_n ${_rep_len})
        endif()
        string(SUBSTRING "${_pin}" 0 ${_n} _pin_prefix)
        string(SUBSTRING "${_reported}" 0 ${_n} _rep_prefix)
        if(NOT _pin_prefix STREQUAL _rep_prefix)
            message(FATAL_ERROR
                "TC8: the resolved sce-codegen was built from a different SCE "
                "revision than this repository vendors:\n"
                "  vendored pin (third_party/sce/VERSION) = ${_pin}\n"
                "  generator reports (--version)          = ${_reported}\n"
                "  generator                              = ${SCE_CODEGEN}\n"
                "Rebuild sce-codegen from the pinned revision, or re-vendor the "
                "snapshot to the generator's revision. The templates and the "
                "renderer move together; a mismatched pair fails at render time "
                "with a message that names neither side.")
        endif()
        message(STATUS
            "TC8: SCE pin ${_pin} — generator reports ${_reported}, revisions agree")
    else()
        # Not a pass. The check could not run, and saying so is the point: a
        # silent skip here reads exactly like a green check to whoever scans the
        # configure log.
        message(STATUS
            "TC8: SCE pin ${_pin} — generator reports no revision (a build made "
            "before upstream stamped the commit into --version), so the revision "
            "comparison could not run; only the render probe below covers this")
    endif()

    set(_probe_dir "${CMAKE_BINARY_DIR}/sce_pin_probe")
    file(MAKE_DIRECTORY "${_probe_dir}")
    file(WRITE "${_probe_dir}/tc8_pin_probe.scxml"
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<scxml xmlns=\"http://www.w3.org/2005/07/scxml\" version=\"1.0\" "
        "name=\"tc8_pin_probe\" datamodel=\"null\" initial=\"s0\">\n"
        "  <state id=\"s0\"><transition event=\"go\" target=\"s1\"/></state>\n"
        "  <final id=\"s1\"/>\n</scxml>\n")

    set(_cmd "${SCE_CODEGEN}" generate "${_probe_dir}/tc8_pin_probe.scxml"
             -o "${_probe_dir}" -l cpp)
    if(SCE_TEMPLATE_DIR)
        set(_cmd ${CMAKE_COMMAND} -E env "SCE_TEMPLATE_DIR=${SCE_TEMPLATE_DIR}" ${_cmd})
    endif()

    execute_process(COMMAND ${_cmd}
        RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_VARIABLE _err)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR
            "TC8: the resolved sce-codegen cannot render the vendored SCE "
            "templates (rc=${_rc}).\n"
            "  generator     = ${SCE_CODEGEN}\n"
            "  vendored pin  = ${_pin}\n"
            "  template dir  = ${SCE_TEMPLATE_DIR}\n"
            "A generator built from a different revision than the templates it "
            "is handed fails this way. Rebuild sce-codegen from the pinned "
            "revision above, or re-vendor the snapshot to match the generator.\n"
            "Generator said:\n${_err}")
    endif()

    message(STATUS "TC8: SCE pin ${_pin} — snapshot self-consistent, generator renders it")
endfunction()

tc8_check_sce_pin()
