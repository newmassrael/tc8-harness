# Standalone AUTOSAR Testability Upper Tester Module (UTM).
#
# Reuses dut_service/testability_server.cpp + the shared codec header verbatim
# (no vsomeip / CommonAPI / ETS dependency) behind a thin signal-driven main().
# The server source is compiled with the same warning treatment it gets inside
# tc8-dut (the strict first-party gate is not applied here, so the file stays
# byte-for-byte the same translation unit); only utm_main.cpp is new code.
add_executable(tc8-utm
    utm_main.cpp
    ${PROJECT_SOURCE_DIR}/dut/dut_service/testability_server.cpp
)
target_include_directories(tc8-utm PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/dut/dut_service
)
