# ── Out-of-tree UTM SDK install/export (PRS_TPSP §6.6 stateful extension) ─────
# include()'d from the top-level CMakeLists AFTER add_subdirectory(dut) so
# tc8_testability_server (and the rest of the exported closure) already exist.
# include() — not add_subdirectory — so this runs in the top-level scope: every
# target it installs and every variable it reads (TC8_UTM_ENGINES, the
# CMAKE_INSTALL_* dirs, CMAKE_CURRENT_BINARY_DIR = the top-level build dir)
# resolve exactly as they did when this lived inline.

# ── Out-of-tree UTM SDK (PRS_TPSP §6.6 stateful extension) ──
# Export the vendor-neutral testability UTM — the ProtocolServer, the
# MiddlewareModule / MiddlewareContext seam, and the POSIX SocketBackend — as a
# find_package(tc8-utm) package so a separate, PRIVATE OEM repository links it
# and attaches its own service-group modules without vendoring this tree. The
# exported surface is public-standard only (AUTOSAR Testability + IETF RFC); it
# carries no OEM-specific content. Install with: cmake --install <build>
# --component utm-sdk --prefix <dir>.
#
# Both halves of the protocol ship: the DUT-side endpoint above and the
# tester-side client (tc8_testability_client) that drives it. A module attached to
# the endpoint is only reachable over the wire, so exporting the endpoint alone
# would leave each consumer to hand-roll a client and re-derive the framing rules
# include/tc8/testability_protocol.h owns. The client speaks the standard protocol
# and carries no OEM content, so it belongs on this same standard-only surface.
# utm_export_smoke holds the pairing: its consumer drives its own registered
# module through the exported client, so dropping either half fails the gate.
option(TC8_UTM_INSTALL
    "Install the testability UTM (DUT endpoint + tester client) as a find_package(tc8-utm) package"
    ON)

if(TC8_UTM_INSTALL AND TARGET tc8_testability_server)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    # Install-tree include root for the exported targets (the build-tree paths
    # are already BUILD_INTERFACE-scoped, so this is purely additive).
    target_include_directories(tc8_wire INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The ports target carries the install-tree include root for the seam headers;
    # the core, the POSIX backend, and the alias all inherit it via their link to
    # the ports.
    target_include_directories(tc8_testability_ports INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The POSIX adapter also installs its own header (posix_socket_backend.h) at the
    # include root, so it carries the install include for consumers of that header.
    target_include_directories(tc8_posix_backend INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The tester-side client installs its own header (tc8/testability_client.h) and
    # reaches the codec SSOT (tc8/testability_protocol.h) — both under the one
    # install-tree include root, which its BUILD_INTERFACE include root collapses onto.
    target_include_directories(tc8_testability_client INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # AUTOSAR engines join the same exported surface so the OEM repo links the
    # mechanism it composes with its config. The set is TC8_UTM_ENGINES, built up
    # by tc8_add_engine() — there is one engine list, so the export cannot drift
    # from the build. The utm_export_smoke gate (the consumer calls each engine)
    # then fails if one is dropped from the export.
    foreach(_eng ${TC8_UTM_ENGINES})
        target_include_directories(${_eng} INTERFACE
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    endforeach()

    # Export the ports (the seam), the split archives (core + POSIX adapter), the
    # INTERFACE convenience union, and the tester-side client. install(EXPORT)
    # checks the link closure, so a target that an exported one LINKS must itself
    # be exported — that is what protects tc8_wire and tc8_testability_ports, and
    # a dropped one fails install rather than a consumer. It does NOT protect the
    # closure roots: nothing links the client or the engines, so dropping either
    # leaves install(EXPORT) happy and breaks the consumer's find_package instead.
    # Those are held by utm_export_smoke, which links and drives them.
    install(TARGETS tc8_testability_server tc8_testability_core tc8_posix_backend
            tc8_testability_ports tc8_wire tc8_testability_client ${TC8_UTM_ENGINES}
        EXPORT tc8-utm-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT utm-sdk)

    # The codec SSOT — shared by the exported client and the exported endpoint, the
    # reason both decode identically.
    # Every public header ships under ONE namespaced root, include/tc8/ — never a
    # bare net/ or wire/ in the consumer's include path. An SDK cannot know what
    # else shares the prefix it is installed into (/usr/local is the common case),
    # and `net/socket_backend.h` or `wire/ip_checksum.h` are names an OEM tree
    # plausibly owns too; only the tc8/ prefix makes the spelling unambiguous.
    # The layout mirrors the source tree under include/tc8/ exactly, so the in-tree
    # and install-tree spellings are identical and cannot drift apart.
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/testability_protocol.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)
    # The tester-side client: the standard primitives plus the generic
    # testabilityCall engine an OEM's own typed wrappers build on. Sits beside the
    # codec it frames against — the protocol's two public faces, one directory.
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/testability_client.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/middleware.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/protocol_server.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/socket_backend.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/io_multiplexer.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/reactor.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/testability COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/net/socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/net COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/include/tc8/wire/icmp_echo.h
            ${PROJECT_SOURCE_DIR}/include/tc8/wire/ip_checksum.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/wire COMPONENT utm-sdk)
    # One engine header per engine, globbed so a new engine's header installs
    # without a second list. include/tc8/autosar/ holds exactly the public engine
    # headers, so the glob cannot sweep an internal one into the export.
    file(GLOB _tc8_autosar_headers CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/include/tc8/autosar/*.h)
    install(FILES ${_tc8_autosar_headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/autosar COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/posix_socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)

    # ── The SDK's runnable tool: tc8-testability-send ──
    # The exported client library lets a consumer speak the protocol, but the
    # only CLI that addresses an arbitrary (GID, PID) — testability-send — lives
    # in the tc8-harness executable, which an SDK-only build gates off
    # (TC8_BUILD_HARNESS=OFF, no vsomeip/libpcap/libtins). So the SDK ships that
    # command as its own standalone executable: a consumer that links tc8-utm and
    # attaches its service groups gets a runnable way to drive the standard groups
    # its DUT now serves, without rebuilding the wire runner it configured out.
    #
    # It compiles the SAME command TU the harness does (testability_send_command
    # .cpp) behind a thin main, and links only the exported tc8_testability_client
    # (POSIX sockets + the header-only codec SSOT) and header-only CLI11 — none of
    # the harness's heavy prerequisites — so there is one codec/client path and the
    # two footprints cannot drift. Guarded by the SDK-install path, not
    # TC8_BUILD_HARNESS, so it is present exactly when the SDK it serves is.
    add_executable(tc8-testability-send
        ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_send_main.cpp
        ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_send_command.cpp)
    # Only the command header it shares with the harness (cli/testability_send_command
    # .h, from the tester-command include root) plus header-only CLI11; the tc8/...
    # protocol + client headers arrive via tc8_testability_client's public include/.
    # No flat src/ root — this SDK tool depends on nothing else under the source tree.
    target_include_directories(tc8-testability-send PRIVATE
        ${PROJECT_SOURCE_DIR}/src/cli/commands/include
        ${PROJECT_SOURCE_DIR}/third_party/CLI11)
    target_link_libraries(tc8-testability-send PRIVATE tc8_testability_client)
    tc8_enable_strict_warnings(tc8-testability-send)
    install(TARGETS tc8-testability-send
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT utm-sdk)

    # ── Optional lwIP backend (utm-sdk-lwip component) ──
    # SDK surface: the lwIP SocketBackend bridge + the self-contained UTM lwipopts.
    # Shipped as SOURCE because they compile against the OEM's own (target-specific)
    # lwIP stack — the SDK ships the bridge to the testability seam, not the stack.
    # These are the EXACT files the in-tree tc8-lwip-utm builds (dut/lwip_dut), so
    # build-lwip-dut keeps them compiling — no hand-copy to drift. An lwIP OEM
    # installs utm-sdk too (the bridge's header pulls in net/ + testability/, the
    # .cpp pulls in wire/), compiles lwip_socket_backend.cpp into its UTM against
    # lwip/lwipopts.h, and links tc8::tc8_testability_core (the backend-agnostic
    # core, no POSIX adapter).
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT utm-sdk-lwip)
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_socket_backend.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)
    # The UTM lwIP config: lwipopts_base.h (the product-neutral infra shared with
    # the conformance fixture — single source of truth) + the utm/ layer (LWIP_IGMP
    # + multicast TX for join/leave; lwIP's default assert, no fixture sink) which
    # #includes "../lwipopts_base.h". Both ship preserving that relative layout, so
    # point lwIP at lwip/utm/. These are the exact files the in-tree tc8-lwip-utm
    # compiles, so the reference cannot drift. The lwIP stack and the final config
    # are the OEM's — a working reference.
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwipopts_base.h
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/utm/lwipopts.h
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip/utm COMPONENT utm-sdk-lwip)
    # The UTM's RFC 6528 ISN generator, named by utm/lwipopts.h's LWIP_HOOK_TCP_ISN /
    # LWIP_HOOK_FILENAME. tc8-owned and self-contained: the hook header (named by the
    # lwipopts so the OEM's lwIP core resolves it on the include path), the bring-up
    # seed seam, and the AES-CMAC implementation. The OEM compiles tc8_lwip_tcp_isn.cpp
    # into its UTM and links the already-exported AES-CMAC engine (utm-sdk's
    # tc8::...crypto) — there is NO dependency on the lwIP-contrib tcp_isn addon, the
    # PPP tree, or its MD5: the exported stack config builds from these files plus the
    # OEM's own lwIP checkout. These are the exact files tc8-lwip-utm compiles, so the
    # reference cannot drift. Shipped next to lwipopts_base.h (the dir the OEM puts on
    # the include path for the hook header).
    install(FILES
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_utm_hooks.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_isn.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_tcp_isn.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)

    # EXAMPLE (not stable SDK surface): the stack bring-up. Bringing the stack up —
    # netif selection, address, RFC 6528 ISN seed, process park — is the composition
    # root's job and is target-specific (a real embedded netif replaces this
    # unix-tapif version). Shipped under example/ as a working reference the OEM
    # copies and adapts; it needs the unix-port default_netif on the OEM's lwIP
    # include path and the ISN seam impl above. It is fixture-free (fault hooks come
    # via the afterNetifUp callback, the assert sink stays in the DUT), and it seeds
    # the ISN through the tc8_lwip_isn.h seam, so it carries no contrib dependency.
    install(FILES
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_stack_bringup.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_stack_bringup.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip/example COMPONENT utm-sdk-lwip)

    install(EXPORT tc8-utm-targets
        NAMESPACE tc8::
        FILE tc8-utm-targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm COMPONENT utm-sdk)

    configure_package_config_file(
        ${PROJECT_SOURCE_DIR}/cmake/tc8-utm-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/tc8-utm-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/tc8-utm-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm COMPONENT utm-sdk)

    # Make the export a verified gate: a CTest that installs the utm-sdk to a
    # temp prefix and builds examples/oem-utm-consumer against it via
    # find_package(tc8-utm). Runs in the same `ctest` the build-test CI job runs,
    # so a dropped header or broken install-interface fails CI, not a human.
    if(TC8_BUILD_UNIT_TESTS)
        add_test(NAME utm_export_smoke
            COMMAND ${CMAKE_COMMAND}
                -DTC8_BUILD_DIR=${CMAKE_BINARY_DIR}
                -DTC8_SOURCE_DIR=${PROJECT_SOURCE_DIR}
                -DTC8_CMAKE=${CMAKE_COMMAND}
                -DTC8_GENERATOR=${CMAKE_GENERATOR}
                -P ${PROJECT_SOURCE_DIR}/cmake/verify-utm-export.cmake)
    endif()
endif()
