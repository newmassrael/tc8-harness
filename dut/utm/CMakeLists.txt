# Standalone AUTOSAR Testability Upper Tester Module (UTM).
#
# Links the shared tc8_testability_server library (the same translation unit the
# DUT service and the unit test use) behind a thin signal-driven main(); no
# vsomeip / CommonAPI / ETS dependency. The library's PUBLIC include surface
# carries the codec header and testability_server.h, so only utm_main.cpp is new.
add_executable(tc8-utm utm_main.cpp)
target_link_libraries(tc8-utm PRIVATE tc8_testability_server)
# vsomeip-free first-party executable — gets the full strict set like the
# testability cores it links.
tc8_enable_strict_warnings(tc8-utm)
