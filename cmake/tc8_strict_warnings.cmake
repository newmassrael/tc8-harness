# Single source of truth for the first-party strict-warning set.
#
# Both top-level builds include() this module so the warning set cannot drift
# between them:
#   * the main harness build (root CMakeLists.txt), which applies it per-target
#     via tc8_enable_strict_warnings(<target>);
#   * the separate lwIP DUT sub-project (dut/lwip_dut/CMakeLists.txt), which
#     applies the options per-source-file (tc8_strict_source_options), because its
#     first-party C++ adapters share an executable target with lwIP's own C sources
#     and the already-strict shared cores — a target-wide gate would hit those too.
#
# The TC8_WARNINGS_AS_ERRORS option is declared HERE, not by each includer, so the
# default lives in exactly one place; both builds get it from this include (each
# build tree still keeps its own cache entry, and option() is idempotent across
# the two includes). The "flags + conditional -Werror" decision likewise lives in
# one helper (tc8_strict_source_options) that both the target form and the lwIP
# per-source form consume — so neither the flag list nor the -Werror gate is copied.

option(TC8_WARNINGS_AS_ERRORS
    "Promote compiler warnings to errors on first-party targets"
    ON)

# The first-party strict-warning flags (GCC/Clang). -Werror is added by
# tc8_strict_source_options when TC8_WARNINGS_AS_ERRORS is ON, so a warnings-only
# build keeps the diagnostics without failing.
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

# Resolve the strict compile options for one consumer into out_var: the flag set
# plus -Werror when TC8_WARNINGS_AS_ERRORS is ON, or empty on a non-GCC/Clang
# compiler (the flags are GCC/Clang spellings). The single home for the
# "flags + conditional -Werror + compiler guard" decision; read at call time so
# the includer's option value is honored.
function(tc8_strict_source_options out_var)
    set(_opts "")
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(_opts ${TC8_STRICT_WARNING_FLAGS})
        if(TC8_WARNINGS_AS_ERRORS)
            list(APPEND _opts -Werror)
        endif()
    endif()
    set(${out_var} ${_opts} PARENT_SCOPE)
endfunction()

# Apply the strict options to a whole first-party target. Used by the main build,
# where every first-party target is built only from first-party translation units.
function(tc8_enable_strict_warnings target)
    tc8_strict_source_options(_opts)
    if(_opts)
        target_compile_options(${target} PRIVATE ${_opts})
    endif()
endfunction()
