# Which in-tree case directories an alias pointer's target names.
#
# An alias (src/harness/CMakeLists.txt, Pass 4) gives an in-tree case a second identity
# in another suite's catalog. Configure verifies that the target exists, and what it
# verifies has to be what CaseRegistry::addAlias resolves at startup, or a pointer
# configure accepts is refused at run time, or one configure refuses is a valid pointer.
#
# A case is one of two shapes (case_iteration.h):
#   * a plain case, with a directory of its own: tests/<id>/
#   * a case made of iterations, with none of its own and one directory per iteration:
#     tests/<id>_it<n>/
# The pointer's optional `iteration <n>` line names one iteration, or none to name the
# whole case. It is a function and not inline so cmake/test-alias-target-units.cmake can
# drive it against a fixture tree; the Pass 4 loop cannot be run on its own.
#
#   tc8_alias_target_units(<tests_dir> <target_dir> <target_label> <iteration>
#                          <units_var> <error_var>)
#
#   tests_dir     the directory holding the case directories
#   target_dir    the target's lower-cased case id
#   target_label  how the target is named in a message
#   iteration     the pointer's `iteration <n>`, 0 when it has none
#   units_var     out: the case directories the pointer covers (empty on error)
#   error_var     out: why the pointer is refused, empty when it is accepted
function(tc8_alias_target_units tests_dir target_dir target_label iteration units_var error_var)
    set(_units "")
    set(_error "")

    file(GLOB _it_dirs LIST_DIRECTORIES true RELATIVE "${tests_dir}"
         "${tests_dir}/${target_dir}_it[1-9]")
    list(SORT _it_dirs)
    # list(FIND), not `IN_LIST`: this runs under `cmake -P` in the test, where policy
    # CMP0057 is unset and IN_LIST is not an operator, as well as under the project.
    list(FIND _it_dirs "${target_dir}_it${iteration}" _at)

    if(IS_DIRECTORY "${tests_dir}/${target_dir}")
        if(NOT iteration EQUAL 0)
            set(_error "`iteration ${iteration}` names an iteration of '${target_label}', "
                       "which is not made of iterations")
        else()
            set(_units "${target_dir}")
        endif()
    elseif(_it_dirs)
        if(iteration EQUAL 0)
            set(_units ${_it_dirs})
        elseif(NOT _at EQUAL -1)
            set(_units "${target_dir}_it${iteration}")
        else()
            list(JOIN _it_dirs ", " _have)
            set(_error "target '${target_label}' has no iteration ${iteration} "
                       "(it has: ${_have})")
        endif()
    else()
        set(_error "target '${target_label}' names no in-tree case "
                   "(no tests/${target_dir}/ and no tests/${target_dir}_it<n>/)")
    endif()

    string(JOIN "" _error ${_error})
    set(${units_var} "${_units}" PARENT_SCOPE)
    set(${error_var} "${_error}" PARENT_SCOPE)
endfunction()
