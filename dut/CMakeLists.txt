find_program(COMMONAPI_CORE_GEN   commonapi-core-generator   REQUIRED)
find_program(COMMONAPI_SOMEIP_GEN commonapi-someip-generator REQUIRED)

add_subdirectory(ets)
add_subdirectory(dut_service)
add_subdirectory(utm)
