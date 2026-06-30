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
set(_oem_ids "DS_[A-Z][A-Z]_[0-9]|HKMC|SOMEIPSRV_CAN_[0-9]")
set(_markers "${_banners}|${_oem_ids}")
# Interface/case-definition files (.fidl/.fdepl/.scxml) and the X-macro SSOT .def
# files are scanned too: they are exactly the surfaces whose public/OEM boundary the
# ETS, case, and wire-SSOT headers document, so a banner or OEM id pasted into a
# fidl, a case SCXML, or a .def must fail here, not slip through because the gate
# only looked at C++. unit_tests is scanned alongside tests so a leak in a gtest TU
# cannot slip past either.
set(_roots src include dut examples tests unit_tests)
set(_hits "")

foreach(root ${_roots})
    file(GLOB_RECURSE files
        ${TC8_SOURCE_DIR}/${root}/*.h
        ${TC8_SOURCE_DIR}/${root}/*.hpp
        ${TC8_SOURCE_DIR}/${root}/*.c
        ${TC8_SOURCE_DIR}/${root}/*.cpp
        ${TC8_SOURCE_DIR}/${root}/*.md
        ${TC8_SOURCE_DIR}/${root}/*.fidl
        ${TC8_SOURCE_DIR}/${root}/*.fdepl
        ${TC8_SOURCE_DIR}/${root}/*.scxml
        ${TC8_SOURCE_DIR}/${root}/*.def)
    foreach(f ${files})
        file(STRINGS ${f} matched REGEX "${_markers}")
        if(matched)
            set(_hits "${_hits}${f}:\n")
            foreach(line ${matched})
                set(_hits "${_hits}    ${line}\n")
            endforeach()
        endif()
    endforeach()
endforeach()

if(NOT _hits STREQUAL "")
    message(FATAL_ERROR
        "NDA-hygiene: confidentiality banner(s) or OEM identifier(s) found — "
        "OEM-proprietary content must not enter this public repo:\n${_hits}")
endif()

message(STATUS "NDA-hygiene: clean (no confidentiality banners or OEM identifiers in src/include/dut/examples/tests/unit_tests, incl. .fidl/.fdepl/.scxml/.def).")
