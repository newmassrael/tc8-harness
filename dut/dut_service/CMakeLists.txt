add_executable(tc8-dut
    client_mode.cpp
    client_mode_proxy.cpp
    dhcpv4_client.cpp
    dut_main.cpp
    ets_impl.cpp
    ets_impl_2.cpp
    linklocal_autoconf.cpp
    upper_tester_server.cpp
    ${PROJECT_SOURCE_DIR}/src/wire/ip_checksum.cpp
)
target_include_directories(tc8-dut PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)
target_link_options(tc8-dut PRIVATE -Wl,--no-as-needed)
target_link_libraries(tc8-dut PRIVATE ets ets2 ets3)
