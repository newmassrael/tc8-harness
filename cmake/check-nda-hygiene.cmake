# NDA-hygiene lint (Part F of the UTM SDK). This repository is public-standard
# only — OA TC8 v3.0, public AUTOSAR specs, and IETF RFCs (see README); all
# OEM-proprietary material (frame layouts, ports, signal/PDU databases, cluster
# maps, timings, keys, test-case / document IDs) lives in the separate, private
# OEM UTM repository. This check fails the build if a confidentiality *banner* —
# the usual signature of pasted proprietary content — appears in the tracked
# source, so a leak fails CI rather than a reviewer's eye.
#
# It deliberately matches uppercase banners only (CONFIDENTIAL, DO NOT
# DISTRIBUTE, ...), not the lowercase word "proprietary" the design comments use
# to *describe* the NDA boundary. It is a backstop, not a substitute for the
# mnemosyne citation gate or review: it catches marked content, not unmarked
# proprietary values. Run as the `nda_hygiene` CTest. Invoke with
# -DTC8_SOURCE_DIR=<repo root>.
cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED TC8_SOURCE_DIR)
    message(FATAL_ERROR "check-nda-hygiene: TC8_SOURCE_DIR must be set")
endif()

set(_markers "CONFIDENTIAL|DO NOT DISTRIBUTE|INTERNAL USE ONLY|RESTRICTED DISTRIBUTION|PROPRIETARY AND CONFIDENTIAL")
set(_roots src include dut examples)
set(_hits "")

foreach(root ${_roots})
    file(GLOB_RECURSE files
        ${TC8_SOURCE_DIR}/${root}/*.h
        ${TC8_SOURCE_DIR}/${root}/*.hpp
        ${TC8_SOURCE_DIR}/${root}/*.c
        ${TC8_SOURCE_DIR}/${root}/*.cpp
        ${TC8_SOURCE_DIR}/${root}/*.md)
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
        "NDA-hygiene: confidentiality banner(s) found — OEM-proprietary content "
        "must not enter this public repo:\n${_hits}")
endif()

message(STATUS "NDA-hygiene: clean (no confidentiality banners in src/include/dut/examples).")
