# NDA-hygiene lint (Part F of the UTM SDK). This repository is public-standard
# only — OA TC8 v3.0, public AUTOSAR specs, and IETF RFCs (see README); all
# OEM-proprietary material (frame layouts, ports, signal/PDU databases, cluster
# maps, timings, keys, test-case / document IDs) lives in the separate, private
# OEM UTM repository. This check fails the build if a confidentiality *banner* —
# the usual signature of pasted proprietary content — OR a known OEM-proprietary
# *identifier* appears in the tracked source, so a leak fails CI rather than a
# reviewer's eye.
#
# It matches two things: (1) uppercase confidentiality banners (CONFIDENTIAL, DO
# NOT DISTRIBUTE, ...), not the lowercase word "proprietary" the design comments
# use to *describe* the NDA boundary; and (2) a small denylist of OEM identifiers
# that have no public-spec meaning, so their presence is an unmarked-content leak
# the banner check alone misses — the OEM CAN-requirement ids (DS_CN_n) and the
# OEM name (HKMC). It is a backstop, not a substitute for the mnemosyne citation
# gate or review: it catches marked banners and these known OEM tokens, not every
# unmarked proprietary value. Run as the `nda_hygiene` CTest. Invoke with
# -DTC8_SOURCE_DIR=<repo root>.
cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED TC8_SOURCE_DIR)
    message(FATAL_ERROR "check-nda-hygiene: TC8_SOURCE_DIR must be set")
endif()

# Uppercase confidentiality banners — the usual signature of pasted content.
set(_banners "CONFIDENTIAL|DO NOT DISTRIBUTE|INTERNAL USE ONLY|RESTRICTED DISTRIBUTION|PROPRIETARY AND CONFIDENTIAL")
# OEM-proprietary identifiers with no public-spec meaning, so their presence is an
# unmarked-content leak: the OEM requirement-id families (DS_CN / DS_ID / DS_SD /
# DS_SP _n, from the OEM NDA spec), the OEM-only case family (SOMEIPSRV_CAN_n), and
# the OEM name. `DS_[A-Z][A-Z]_[0-9]` covers all four DS_* families (current and
# future) and is collision-free against public tokens. Distinct from RFC /
# public-spec section refs (e.g. "RFC 6298 §5.3") and the public SOMEIPSRV_RPC / _SD
# families, which these patterns do not match.
# The OEM name is matched case-INSENSITIVELY (`[Hh][Kk]...`): unlike the banners
# above it has no legitimate lowercase sense, and a lowercase `hkmc:` suite prefix
# in a shell/awk comment is exactly how it previously slipped a case-sensitive
# `HKMC`. The DS_ / CAN families stay upper-anchored (they are upper-case by spec).
set(_oem_ids "DS_[A-Z][A-Z]_[0-9]|[Hh][Kk][Mm][Cc]|SOMEIPSRV_CAN_[0-9]")
set(_markers "${_banners}|${_oem_ids}")
# Interface/case-definition files (.fidl/.fdepl/.scxml) and the X-macro SSOT .def
# files are scanned too: they are exactly the surfaces whose public/OEM boundary the
# ETS, case, and wire-SSOT headers document, so a banner or OEM id pasted into a
# fidl, a case SCXML, or a .def must fail here, not slip through because the gate
# only looked at C++. unit_tests is scanned alongside tests so a leak in a gtest TU
# cannot slip past either. The shell/awk orchestration layer (.sh/.awk), the Python
# tooling and CI workflows (.py/.yml), and the scripts/ + docs/ + tools/ + .github/
# roots are scanned as well: an OEM suite prefix in a smoke-test comment previously
# evaded this gate purely because .sh was not globbed and those roots were not walked.
#
# The build system (CMakeLists.txt, *.cmake, *.cmake.in, cmake/) is scanned for the
# same reason, and it escaped for the same reason: it is authored prose-bearing
# source, it is where architectural and NDA-boundary rationale naturally accretes,
# and neither its extensions nor the cmake/ root were covered — so every build file
# in the repo, including THIS gate, was invisible to it. That is the .sh escape
# repeating one extension later, which is the standing weakness of an
# extension-allowlist: it is only ever as complete as the last leak. Adding a file
# type here is therefore mandatory, not optional, and the neg-control (plant a token,
# watch the gate fail) is what proves the addition took.
#
# Vendored third_party/ is deliberately excluded — its content is not ours to police.
set(_roots src include dut examples tests unit_tests scripts docs tools .github cmake)
set(_files "")

foreach(root ${_roots})
    file(GLOB_RECURSE _rootfiles
        ${TC8_SOURCE_DIR}/${root}/*.h
        ${TC8_SOURCE_DIR}/${root}/*.hpp
        ${TC8_SOURCE_DIR}/${root}/*.c
        ${TC8_SOURCE_DIR}/${root}/*.cpp
        ${TC8_SOURCE_DIR}/${root}/*.md
        ${TC8_SOURCE_DIR}/${root}/*.fidl
        ${TC8_SOURCE_DIR}/${root}/*.fdepl
        ${TC8_SOURCE_DIR}/${root}/*.scxml
        ${TC8_SOURCE_DIR}/${root}/*.def
        ${TC8_SOURCE_DIR}/${root}/*.sh
        ${TC8_SOURCE_DIR}/${root}/*.awk
        ${TC8_SOURCE_DIR}/${root}/*.py
        ${TC8_SOURCE_DIR}/${root}/*.yml
        ${TC8_SOURCE_DIR}/${root}/CMakeLists.txt
        ${TC8_SOURCE_DIR}/${root}/*.cmake
        ${TC8_SOURCE_DIR}/${root}/*.cmake.in)
    list(APPEND _files ${_rootfiles})
endforeach()

# The top-level CMakeLists.txt sits in no root, so the loop above cannot reach it —
# and it is the single largest authored build file in the repo (the case registry,
# the UTM SDK export, every option's rationale). Named explicitly rather than by
# globbing the repo root, which would sweep vendored and generated trees back in.
list(APPEND _files ${TC8_SOURCE_DIR}/CMakeLists.txt)

# This file defines the denylist, so it necessarily SPELLS every token it hunts —
# scanning it would make the gate fail on its own patterns, forever. It is the one
# self-reference the cmake/ root introduces, and the exclusion is narrow: exactly
# the gate's own source, by exact path, never a pattern that could widen. The cost
# is that this file cannot police itself; the mitigation is that its whole content
# IS the policy under review, so a token pasted here is a review-visible change to
# the gate rather than a leak hidden in unrelated code.
list(REMOVE_ITEM _files ${CMAKE_CURRENT_LIST_FILE})

# The Astro case-doc site (site/) is publicly deployed (GitHub Pages) and, via the
# SITE_EXTRA_CASE_ROOTS overlay, is an OEM-content-adjacent surface — so its tracked
# authored source is scanned too: Astro components/lib/pages (.astro/.ts), the
# manifest/message tooling (.py), root config (.mjs), and the per-case locale
# overrides (.json under src/locales/). Recursion is scoped to site/src + site/scripts
# (no vendored node_modules there) plus root config. Generated output is excluded —
# src/data/ in particular may hold locally-staged, git-ignored SITE_EXTRA_CASE_ROOTS
# overlay content, which is intentional and must never be read as a leak.
file(GLOB_RECURSE _sitefiles
    ${TC8_SOURCE_DIR}/site/src/*.astro
    ${TC8_SOURCE_DIR}/site/src/*.ts
    ${TC8_SOURCE_DIR}/site/src/*.json
    ${TC8_SOURCE_DIR}/site/scripts/*.py)
list(FILTER _sitefiles EXCLUDE REGEX "/site/src/data/")
file(GLOB _sitecfg
    ${TC8_SOURCE_DIR}/site/*.mjs
    ${TC8_SOURCE_DIR}/site/*.md)
list(APPEND _files ${_sitefiles} ${_sitecfg})

set(_hits "")
foreach(f ${_files})
    file(STRINGS ${f} matched REGEX "${_markers}")
    if(matched)
        set(_hits "${_hits}${f}:\n")
        foreach(line ${matched})
            set(_hits "${_hits}    ${line}\n")
        endforeach()
    endif()
endforeach()

if(NOT _hits STREQUAL "")
    message(FATAL_ERROR
        "NDA-hygiene: confidentiality banner(s) or OEM identifier(s) found — "
        "OEM-proprietary content must not enter this public repo:\n${_hits}")
endif()

list(LENGTH _files _n_scanned)
message(STATUS
    "NDA-hygiene: clean — ${_n_scanned} authored file(s): "
    "src/include/dut/examples/tests/unit_tests/scripts/docs/tools/.github/cmake "
    "(.h/.hpp/.c/.cpp/.md/.fidl/.fdepl/.scxml/.def/.sh/.awk/.py/.yml + "
    "CMakeLists.txt/.cmake/.cmake.in incl. the top-level CMakeLists.txt) "
    "+ site/ (.astro/.ts/.py/.mjs/.json under src/locales, excl. generated src/data). "
    "Excluded: vendored third_party/ and this gate's own source (it spells the denylist).")
