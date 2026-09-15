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
#   * The generator does not report its own revision. At the pinned revision
#     (third_party/sce/VERSION) the CLI carries no commit: `--version` prints a
#     static `sce-codegen 0.1.0`, there is no `GENERATOR_COMMIT` in the crate,
#     and the `generate` stdout manifest has no `generator` field. So there is no
#     second revision to compare the pin against. Upstream grew that field later;
#     until the pin moves past it, a true revision comparison cannot be written
#     here, and writing one that compares the pin to itself would be worse than
#     writing none.
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
