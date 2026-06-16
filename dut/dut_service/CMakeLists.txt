# The AUTOSAR testability endpoint, built once as a library so the DUT service,
# the standalone tc8-utm, and the unit test all link the same translation units.
# Ports & adapters: the platform-agnostic protocol core (src/testability/) plus
# the POSIX SocketBackend adapter. The lwIP DUT fixture compiles the same core
# against its own adapter (dut/lwip_dut/lwip_socket_backend) — a single source
# of truth for the protocol logic across both platforms.
add_library(tc8_testability_server STATIC
    ${PROJECT_SOURCE_DIR}/src/testability/protocol_server.cpp
    posix_socket_backend.cpp
)
target_include_directories(tc8_testability_server PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# The ICMP ECHO_REQUEST primitive frames its packet via the shared wire layer
# (RFC 1071 checksum + RFC 792 echo body); PUBLIC so tc8-dut, tc8-utm and the
# unit test inherit tc8_wire transitively rather than each naming the source.
target_link_libraries(tc8_testability_server PUBLIC tc8_wire)

# The TC8 Upper Tester server, built once as a library so the DUT service and
# the unit test link the same translation units. Ports & adapters: the
# platform-agnostic core (src/upper_tester/) plus the POSIX StackProbe adapter.
# The socket primitives come from tc8::net::SocketBackend (PosixSocketBackend in
# tc8_testability_server), so consumers link that too. The lwIP DUT fixture
# compiles the same core against its own adapters — a single source of truth for
# the UT protocol logic across both platforms.
add_library(tc8_upper_tester_server STATIC
    ${PROJECT_SOURCE_DIR}/src/upper_tester/ut_server.cpp
    posix_stack_probe.cpp
)
target_include_directories(tc8_upper_tester_server PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(tc8-dut
    client_mode.cpp
    client_mode_proxy.cpp
    dhcpv4_client.cpp
    dut_main.cpp
    ets_impl.cpp
    ets_impl_2.cpp
    linklocal_autoconf.cpp
    posix_ut_extensions.cpp
)
target_include_directories(tc8-dut PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)
target_link_options(tc8-dut PRIVATE -Wl,--no-as-needed)
target_link_libraries(tc8-dut PRIVATE ets ets2 ets3 tc8_testability_server tc8_upper_tester_server)
