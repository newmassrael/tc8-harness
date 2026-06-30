# Single source of truth for the first-party strict-warning set.
#
# Both top-level builds include() this module so the warning set cannot drift
# between them:
#   * the main harness build (root CMakeLists.txt), which applies it per-target
#     via tc8_enable_strict_warnings(<target>);
#   * the separate lwIP DUT sub-project (dut/lwip_dut/CMakeLists.txt), which
#     applies TC8_STRICT_WARNING_FLAGS per-source-file, because its first-party
#     C++ adapters share an executable target with lwIP's own C sources and the
#     already-strict shared cores — a target-wide gate would hit those too.
#
# Each includer declares the TC8_WARNINGS_AS_ERRORS option itself (so each build
# owns its own default) before the set is applied; the -Werror promotion below
# reads whatever value the includer set.

# The first-party strict-warning flags (GCC/Clang). -Werror is added separately
# by the consumer, gated on TC8_WARNINGS_AS_ERRORS, so a warnings-only build can
# keep the diagnostics without failing.
set(TC8_STRICT_WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wsign-conversion
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Woverloaded-virtual
    -Wdouble-promotion
    -Wformat=2
)

# Apply the strict set (plus -Werror when TC8_WARNINGS_AS_ERRORS is ON) to a
# whole first-party target. Used by the main build, where every first-party
# target is built only from first-party translation units.
function(tc8_enable_strict_warnings target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE ${TC8_STRICT_WARNING_FLAGS})
        if(TC8_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()
