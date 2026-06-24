# Verifies the tc8-utm export is consumable out-of-tree: installs the utm-sdk
# component to a temp prefix, then configures + builds examples/oem-utm-consumer
# against it via find_package(tc8-utm). Driven as a CTest (see CMakeLists.txt
# utm_export_smoke) so the exported SDK surface is exercised on every run — an
# unverified export silently rots when a header drops off the install list.
#
# Invoked with `cmake -P`; the driver passes TC8_BUILD_DIR / TC8_SOURCE_DIR /
# TC8_CMAKE / TC8_GENERATOR via -D.

set(_root "${TC8_BUILD_DIR}/utm-export-check")
set(_prefix "${_root}/sdk")
set(_consumer "${_root}/consumer")
file(REMOVE_RECURSE "${_root}")

execute_process(
    COMMAND "${TC8_CMAKE}" --install "${TC8_BUILD_DIR}"
            --component utm-sdk --prefix "${_prefix}"
    RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "utm export: install of the utm-sdk component failed (${_rc})")
endif()

set(_gen "")
if(TC8_GENERATOR)
    set(_gen -G "${TC8_GENERATOR}")
endif()
execute_process(
    COMMAND "${TC8_CMAKE}" ${_gen}
            -S "${TC8_SOURCE_DIR}/examples/oem-utm-consumer" -B "${_consumer}"
            "-DCMAKE_PREFIX_PATH=${_prefix}"
    RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "utm export: consumer find_package/configure failed (${_rc})")
endif()

execute_process(
    COMMAND "${TC8_CMAKE}" --build "${_consumer}"
    RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "utm export: consumer link/build failed (${_rc})")
endif()

message(STATUS "utm export: find_package(tc8-utm) consumer configured + built OK")
