# Golden-output driver for `tc8-harness decode-pcap` (ctest: decode_pcap_golden).
# Runs the real binary on the committed fixture pcap + trace and asserts the
# emitted PacketCapture JSON is byte-identical to the committed expected file.
# This is the automated guard for the exporter that replaced the deleted .def
# `--check` gates (see docs/tech-debt.md TD-05). Inputs are passed via -D:
#   BIN PCAP TRACE EXPECTED OUT
execute_process(
    COMMAND "${BIN}" decode-pcap GOLDEN pass "${PCAP}"
            --captured-at "2020-01-01T00:00:00Z"
            --trace-json "${TRACE}"
            --out "${OUT}"
    RESULT_VARIABLE run_rc)
if(NOT run_rc EQUAL 0)
    message(FATAL_ERROR "tc8-harness decode-pcap exited ${run_rc}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E compare_files "${OUT}" "${EXPECTED}"
    RESULT_VARIABLE diff_rc)
if(NOT diff_rc EQUAL 0)
    message(FATAL_ERROR
        "decode-pcap output differs from the golden fixture.\n"
        "  got:      ${OUT}\n"
        "  expected: ${EXPECTED}\n"
        "If the change is intentional, regenerate the fixture and refresh the "
        "expected JSON per the header of "
        "unit_tests/fixtures/gen_decode_pcap_fixture.py.")
endif()
