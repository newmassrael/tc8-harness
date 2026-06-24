# Out-of-tree consumer of the tc8-utm SDK. Stands in for a separate, private OEM
# repository: it find_package()es the installed UTM core, links it, and attaches
# its own MiddlewareModule. Configure with the install prefix on CMAKE_PREFIX_PATH:
#   cmake --install <tc8-build> --component utm-sdk --prefix <sdk>
#   cmake -S examples/oem-utm-consumer -B <c-build> -DCMAKE_PREFIX_PATH=<sdk>
#   cmake --build <c-build>
cmake_minimum_required(VERSION 3.16)
project(oem-utm-consumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(tc8-utm REQUIRED)

add_executable(oem-utm-consumer main.cpp)
# Link the seam plus each exported AUTOSAR engine the OEM module would compose.
# Linking and calling them here is what makes the export a verified gate: drop
# an engine from the install/EXPORT and this out-of-tree build fails to link.
target_link_libraries(oem-utm-consumer PRIVATE
    tc8::tc8_testability_server
    tc8::tc8_crypto
    tc8::tc8_pn
    tc8::tc8_crc
    tc8::tc8_e2e
    tc8::tc8_com)
