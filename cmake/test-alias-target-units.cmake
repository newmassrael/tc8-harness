# Drives tc8_alias_target_units against a fixture tree. Run as
#   cmake -DTC8_SOURCE_DIR=<repo> -DTC8_WORK_DIR=<scratch> -P cmake/test-alias-target-units.cmake
#
# The regression this guards: Pass 4 checked for tests/<id>/ alone, so every pointer at a
# case made of iterations (which has only tests/<id>_it<n>/) was refused at configure, with
# "names no in-tree case", while CaseRegistry::addAlias accepted it at run time.

include(${TC8_SOURCE_DIR}/cmake/tc8_alias_target.cmake)

set(_tests "${TC8_WORK_DIR}/tests")
file(REMOVE_RECURSE "${TC8_WORK_DIR}")
# A plain case, a case made of iterations, and one whose spec skips a number (a case
# declared with numbers "13" has an iteration 1 and an iteration 3 and no 2).
file(MAKE_DIRECTORY "${_tests}/plain_01")
file(MAKE_DIRECTORY "${_tests}/iter_02_it1" "${_tests}/iter_02_it2" "${_tests}/iter_02_it3")
file(MAKE_DIRECTORY "${_tests}/gap_03_it1" "${_tests}/gap_03_it3")
# A neighbour that must not be read as an iteration of `iter_02`.
file(MAKE_DIRECTORY "${_tests}/iter_02_neg")

set(_failures 0)

# expect(<name> <target_dir> <iteration> <want_units> <want_error_substring>)
function(expect name target_dir iteration want_units want_error)
    tc8_alias_target_units("${_tests}" "${target_dir}" "tc8:${target_dir}" "${iteration}"
                           _units _error)
    set(_ok TRUE)
    if(NOT "${_units}" STREQUAL "${want_units}")
        set(_ok FALSE)
    endif()
    if("${want_error}" STREQUAL "")
        if(NOT "${_error}" STREQUAL "")
            set(_ok FALSE)
        endif()
    elseif(NOT "${_error}" MATCHES "${want_error}")
        set(_ok FALSE)
    endif()
    if(NOT _ok)
        message(SEND_ERROR "FAIL ${name}: units=[${_units}] error=[${_error}]; "
                           "wanted units=[${want_units}] error~=[${want_error}]")
    else()
        message(STATUS "ok   ${name}")
    endif()
endfunction()

expect("plain case, no iteration"        plain_01 0 "plain_01" "")
expect("plain case refuses an iteration" plain_01 1 ""          "not made of iterations")
expect("iterated case, whole"            iter_02  0 "iter_02_it1;iter_02_it2;iter_02_it3" "")
expect("iterated case, one iteration"    iter_02  2 "iter_02_it2" "")
expect("iterated case, the last"         iter_02  3 "iter_02_it3" "")
expect("iterated case lacks iteration 4" iter_02  4 ""          "no iteration 4 .it has: iter_02_it1, iter_02_it2, iter_02_it3")
expect("a skipped number is absent"      gap_03   2 ""          "no iteration 2 .it has: gap_03_it1, gap_03_it3")
expect("a skipped number's neighbour"    gap_03   3 "gap_03_it3" "")
expect("unknown case"                    nope_04  0 ""          "names no in-tree case")
expect("unknown case with an iteration"  nope_04  1 ""          "names no in-tree case")
