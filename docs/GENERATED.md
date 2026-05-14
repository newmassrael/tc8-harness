# GENERATED.md — atomic store derived view

this file `mnemosyne-cli generate-docs` output — direct no edit. atomic store (`docs/.atomic/workspace.atomic.json`) in mutate primitive (`set-section-*` / `append-changelog-entry-v2`) pass and then re-generate.

Source: `docs/.atomic/workspace.atomic.json`

---

## Sections

### §4.1. 4.1


**Intent**: TC8 §4.1 — auto-seeded TC8-internal sub-section (11 code citations at baseline).









**Implementations**:
- src/stimulus/someip_rpc_builder.h
- src/stimulus/upper_tester_client.h



### §4.1.1. 4.1.1


**Intent**: TC8 §4.1.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- tests/udp_introduction_01/udp_introduction_01.scxml



### §4.1.3. 4.1.3


**Intent**: TC8 §4.1.3 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- tests/someip_ets_130/someip_ets_130.scxml



### §4.1.5. 4.1.5


**Intent**: TC8 §4.1.5 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someip_ets_055.h



### §4.2. 4.2


**Intent**: TC8 §4.2 — auto-seeded TC8-internal sub-section (40 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/captured_event.h
- include/tc8/protocol_frames/arp_frame.h
- include/tc8/protocol_frames/udp_frame.h
- src/capture/bpf_filter.h
- src/cli/capture_driver.cpp
- src/dissect/packet_pipeline.cpp
- src/dissect/packet_pipeline.h
- src/sce_integration/arp_and_dhcpv4_pilot_common.h
- src/sce_integration/arp_expectations.h
- src/sce_integration/cases/_arp_traits_base.h
- src/sce_integration/cases/arp_40.h
- src/sce_integration/cases/someip_ets_084.h
- src/sce_integration/cases/someip_ets_092.h
- src/sce_integration/cases/someip_ets_155.h
- src/sce_integration/test_case_traits.h
- src/sce_integration/udp_captured.h
- src/stimulus/someip_sd_builder.cpp
- src/stimulus/someip_sd_builder.h
- tests/someip_ets_084/someip_ets_084.scxml
- tests/someip_ets_092/someip_ets_092.scxml
- tests/someip_ets_093/someip_ets_093.scxml



### §4.2.1. 4.2.1


**Intent**: TC8 §4.2.1 — auto-seeded TC8-internal sub-section (6 code citations at baseline).









**Implementations**:
- dut/dut_service/client_mode.cpp
- src/stimulus/someip_sd_builder.cpp
- src/stimulus/someip_sd_builder.h



### §4.2.2. 4.2.2


**Intent**: TC8 §4.2.2 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/someip_captured.h



### §4.2.2.16. 4.2.2.16


**Intent**: TC8 §4.2.2.16 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/tcp_pilot_common.h



### §4.2.2.17. 4.2.2.17


**Intent**: TC8 §4.2.2.17 — auto-seeded TC8-internal sub-section (6 code citations at baseline).









**Implementations**:
- tests/tcp_probing_windows_06/tcp_probing_windows_06.scxml



### §4.2.2.6. 4.2.2.6


**Intent**: TC8 §4.2.2.6 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/tcp_mss_options_10.h



### §4.2.3. 4.2.3


**Intent**: TC8 §4.2.3 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/tcp_header_06.h



### §4.2.3.1. 4.2.3.1


**Intent**: TC8 §4.2.3.1 — auto-seeded TC8-internal sub-section (9 code citations at baseline).









**Implementations**:
- src/sce_integration/tcp_pilot_common.h



### §4.2.4. 4.2.4


**Intent**: TC8 §4.2.4 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- include/tc8/protocol_frames/arp_frame.h
- src/sce_integration/arp_captured.h



### §4.2.4.1. 4.2.4.1


**Intent**: TC8 §4.2.4.1 — ARP — Request/Response cases. 13 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/setup-netns.sh
- dut/env/smoke-test.sh
- src/cli/expect_parser.h
- src/sce_integration/arp_captured.h
- src/sce_integration/arp_expectations.h
- src/sce_integration/arp_expected.h
- src/sce_integration/test_runner.h
- src/stimulus/arp_builder.h
- src/stimulus/icmpv4_builder.h
- tests/arp_03/arp_03.scxml
- tests/arp_04/arp_04.scxml
- tests/arp_05/arp_05.scxml
- tests/arp_06/arp_06.scxml
- tests/arp_07/arp_07.scxml
- tests/arp_08/arp_08.scxml
- tests/arp_09/arp_09.scxml
- tests/arp_10/arp_10.scxml
- tests/arp_11/arp_11.scxml
- tests/arp_12/arp_12.scxml
- tests/arp_13/arp_13.scxml
- tests/arp_14/arp_14.scxml
- tests/arp_15/arp_15.scxml
- tests/arp_21/arp_21.scxml
- tests/tcp_checksum_02/tcp_checksum_02.scxml



### §4.2.4.2. 4.2.4.2


**Intent**: TC8 §4.2.4.2 — ARP — Cache, Probe, Announce, Conflict. 28 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/setup-netns.sh
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/arp_frame.h
- src/capture/pcap_source.cpp
- src/cli/expect_parser.h
- src/sce_integration/arp_captured.h
- src/sce_integration/arp_expectations.h
- src/sce_integration/arp_expected.h
- src/sce_integration/cases/arp_16.h
- src/stimulus/arp_builder.h
- tests/_templates/arp_group_c_cache_merge_second_mac.sce-template.xml
- tests/_templates/arp_group_c_drop_and_emit.sce-template.xml
- tests/_templates/arp_group_d_stateful_learning_observation.sce-template.xml
- tests/arp_16/arp_16.scxml
- tests/arp_17/arp_17.scxml
- tests/arp_18/arp_18.scxml
- tests/arp_19/arp_19.scxml
- tests/arp_20/arp_20.scxml
- tests/arp_21/arp_21.scxml
- tests/arp_22/arp_22.scxml
- tests/arp_26/arp_26.scxml
- tests/arp_27/arp_27.scxml
- tests/arp_28/arp_28.scxml
- tests/arp_32/arp_32.scxml
- tests/arp_33/arp_33.scxml
- tests/arp_34/arp_34.scxml
- tests/arp_35/arp_35.scxml
- tests/arp_36/arp_36.scxml
- tests/arp_37/arp_37.scxml
- tests/arp_38/arp_38.scxml
- tests/arp_39/arp_39.scxml
- tests/arp_40/arp_40.scxml
- tests/arp_41/arp_41.scxml
- tests/arp_42/arp_42.scxml
- tests/arp_43/arp_43.scxml
- tests/arp_44/arp_44.scxml
- tests/arp_45/arp_45.scxml
- tests/arp_46/arp_46.scxml
- tests/arp_47/arp_47.scxml
- tests/arp_48/arp_48.scxml
- tests/arp_49/arp_49.scxml



### §4.3. 4.3


**Intent**: TC8 §4.3 — auto-seeded TC8-internal sub-section (30 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/protocol_frames/icmpv4_frame.h
- src/capture/bpf_filter.h
- src/dissect/packet_pipeline.cpp
- src/dissect/packet_pipeline.h
- src/sce_integration/cases/_icmpv4_traits_base.h
- src/sce_integration/cases/icmpv4_type_04.h
- src/sce_integration/cases/ipv4_fragments_01.h
- src/sce_integration/cases/ipv4_fragments_02.h
- src/sce_integration/icmpv4_expectations.h
- src/sce_integration/icmpv4_pilot_common.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- tests/_templates/icmpv4_negative_absence.sce-template.xml
- tests/icmpv4_type_18/icmpv4_type_18.scxml
- tests/ipv4_reassembly_06/ipv4_reassembly_06.scxml
- tests/ipv4_reassembly_07/ipv4_reassembly_07.scxml
- tests/ipv4_reassembly_09/ipv4_reassembly_09.scxml
- tests/tcp_basics_04/tcp_basics_04.scxml
- tests/tcp_basics_06/tcp_basics_06.scxml
- tests/tcp_closing_13/tcp_closing_13.scxml



### §4.3.1. 4.3.1


**Intent**: TC8 §4.3.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/icmpv4_pilot_common.h
- tests/dhcpv4_client_summary_02/dhcpv4_client_summary_02.scxml



### §4.3.2. 4.3.2


**Intent**: TC8 §4.3.2 — auto-seeded TC8-internal sub-section (6 code citations at baseline).









**Implementations**:
- tests/dhcpv4_client_allocating_03/dhcpv4_client_allocating_03.scxml
- tests/dhcpv4_client_request_02/dhcpv4_client_request_02.scxml



### §4.3.3.1. 4.3.3.1


**Intent**: TC8 §4.3.3.1 — ICMPv4 — Error message handling. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/icmpv4_captured.h
- src/sce_integration/icmpv4_pilot_common.h
- src/stimulus/icmpv4_builder.h
- tests/icmpv4_error_02/icmpv4_error_02.scxml
- tests/icmpv4_error_03/icmpv4_error_03.scxml
- tests/icmpv4_error_04/icmpv4_error_04.scxml
- tests/icmpv4_error_05/icmpv4_error_05.scxml



### §4.3.3.2. 4.3.3.2


**Intent**: TC8 §4.3.3.2 — ICMPv4 — Type-specific message handling. 10 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/cli/expect_parser.h
- src/sce_integration/icmpv4_captured.h
- src/sce_integration/icmpv4_expected.h
- src/sce_integration/icmpv4_pilot_common.h
- src/stimulus/icmpv4_builder.cpp
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- tests/icmpv4_type_04/icmpv4_type_04.scxml
- tests/icmpv4_type_05/icmpv4_type_05.scxml
- tests/icmpv4_type_08/icmpv4_type_08.scxml
- tests/icmpv4_type_09/icmpv4_type_09.scxml
- tests/icmpv4_type_10/icmpv4_type_10.scxml
- tests/icmpv4_type_11/icmpv4_type_11.scxml
- tests/icmpv4_type_12/icmpv4_type_12.scxml
- tests/icmpv4_type_16/icmpv4_type_16.scxml
- tests/icmpv4_type_18/icmpv4_type_18.scxml
- tests/icmpv4_type_22/icmpv4_type_22.scxml
- tests/tcp_checksum_02/tcp_checksum_02.scxml



### §4.3.6. 4.3.6


**Intent**: TC8 §4.3.6 — auto-seeded TC8-internal sub-section (6 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.h



### §4.4. 4.4


**Intent**: TC8 §4.4 — auto-seeded TC8-internal sub-section (29 code citations at baseline).









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/iface_enumeration.h
- include/tc8/protocol_frames/ipv4_frame.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.cpp
- src/capture/bpf_filter.h
- src/cli/expect_parser.h
- src/dissect/packet_pipeline.cpp
- src/sce_integration/cases/_ipv4_traits_base.h
- src/sce_integration/icmpv4_pilot_common.h
- src/sce_integration/ipv4_captured.h
- src/sce_integration/ipv4_expectations.h
- src/sce_integration/ipv4_expected.h
- src/sce_integration/ipv4_pilot_common.h
- src/stimulus/icmpv4_builder.h
- tests/_templates/ipv4_field_check.sce-template.xml
- tests/_templates/ipv4_negative_absence.sce-template.xml
- tests/_templates/ipv4_positive_reply.sce-template.xml
- tests/_templates/ipv4_udp_ut_presence.sce-template.xml
- tests/tcp_closing_13/tcp_closing_13.scxml
- src/dissect/packet_pipeline.h



### §4.4.1. 4.4.1


**Intent**: TC8 §4.4.1 — auto-seeded TC8-internal sub-section (12 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- tests/dhcpv4_client_initialization_allocation_05/dhcpv4_client_initialization_allocation_05.scxml



### §4.4.4. 4.4.4


**Intent**: TC8 §4.4.4 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.h



### §4.4.4.1. 4.4.4.1


**Intent**: TC8 §4.4.4.1 — IPv4 — Header field handling. 7 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/cases/ipv4_header_08.h
- src/sce_integration/cases/ipv4_header_09.h
- src/sce_integration/icmpv4_captured.h
- src/sce_integration/ipv4_pilot_common.h
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- tests/ipv4_header_01/ipv4_header_01.scxml
- tests/ipv4_header_02/ipv4_header_02.scxml
- tests/ipv4_header_03/ipv4_header_03.scxml
- tests/ipv4_header_04/ipv4_header_04.scxml
- tests/ipv4_header_05/ipv4_header_05.scxml
- tests/ipv4_header_08/ipv4_header_08.scxml
- tests/ipv4_header_09/ipv4_header_09.scxml



### §4.4.4.2. 4.4.4.2


**Intent**: TC8 §4.4.4.2 — IPv4 — Checksum. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/cli/expect_parser.h
- src/sce_integration/ipv4_captured.h
- src/sce_integration/ipv4_expected.h
- src/sce_integration/ipv4_pilot_common.h
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- src/stimulus/tcp_segment_builder.h
- tests/ipv4_checksum_02/ipv4_checksum_02.scxml
- tests/ipv4_checksum_05/ipv4_checksum_05.scxml



### §4.4.4.3. 4.4.4.3


**Intent**: TC8 §4.4.4.3 — IPv4 — TTL. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/sce_integration/ipv4_expectations.h
- src/sce_integration/ipv4_pilot_common.h
- tests/ipv4_ttl_01/ipv4_ttl_01.scxml
- tests/ipv4_ttl_05/ipv4_ttl_05.scxml



### §4.4.4.4. 4.4.4.4


**Intent**: TC8 §4.4.4.4 — IPv4 — Version. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/sce_integration/ipv4_expectations.h
- src/sce_integration/ipv4_pilot_common.h
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- tests/ipv4_version_01/ipv4_version_01.scxml
- tests/ipv4_version_03/ipv4_version_03.scxml
- tests/ipv4_version_04/ipv4_version_04.scxml



### §4.4.4.5. 4.4.4.5


**Intent**: TC8 §4.4.4.5 — IPv4 — Addressing. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.cpp
- src/sce_integration/cases/icmpv4_type_18.h
- src/sce_integration/cases/ipv4_addressing_01.h
- src/sce_integration/cases/ipv4_addressing_02.h
- src/sce_integration/ipv4_pilot_common.h
- src/sce_integration/udp_captured.h
- tests/_templates/ipv4_udp_ut_presence.sce-template.xml
- tests/ipv4_addressing_01/ipv4_addressing_01.scxml
- tests/ipv4_addressing_02/ipv4_addressing_02.scxml
- tests/ipv4_addressing_03/ipv4_addressing_03.scxml



### §4.4.4.6. 4.4.4.6


**Intent**: TC8 §4.4.4.6 — IPv4 — Fragments. 5 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/udp_frame.h
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/tcp_flags_invalid_01.h
- src/sce_integration/ipv4_expected.h
- src/sce_integration/ipv4_fragments_common.h
- src/sce_integration/test_case_traits.h
- src/sce_integration/udp_captured.h
- src/sce_integration/udp_pilot_common.h
- src/stimulus/icmpv4_builder.cpp
- src/stimulus/icmpv4_builder.h
- src/stimulus/ipv4_frame_builder.h
- tests/_templates/ipv4_fragments_compound.sce-template.xml
- tests/ipv4_fragments_01/ipv4_fragments_01.scxml
- tests/ipv4_fragments_02/ipv4_fragments_02.scxml
- tests/ipv4_fragments_03/ipv4_fragments_03.scxml
- tests/ipv4_fragments_04/ipv4_fragments_04.scxml
- tests/ipv4_fragments_05/ipv4_fragments_05.scxml
- tests/tcp_flags_invalid_01/tcp_flags_invalid_01.scxml
- dut/dut_service/upper_tester_server.h



### §4.4.4.7. 4.4.4.7


**Intent**: TC8 §4.4.4.7 — IPv4 — Reassembly. 8 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/ipv4_frame.h
- src/sce_integration/ipv4_captured.h
- src/sce_integration/ipv4_fragments_common.h
- src/sce_integration/ipv4_reassembly_common.h
- tests/ipv4_reassembly_04/ipv4_reassembly_04.scxml
- tests/ipv4_reassembly_06/ipv4_reassembly_06.scxml
- tests/ipv4_reassembly_07/ipv4_reassembly_07.scxml
- tests/ipv4_reassembly_09/ipv4_reassembly_09.scxml
- tests/ipv4_reassembly_10/ipv4_reassembly_10.scxml
- tests/ipv4_reassembly_11/ipv4_reassembly_11.scxml
- tests/ipv4_reassembly_12/ipv4_reassembly_12.scxml
- tests/ipv4_reassembly_13/ipv4_reassembly_13.scxml



### §4.4.5. 4.4.5


**Intent**: TC8 §4.4.5 — auto-seeded TC8-internal sub-section (26 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_pilot_common.h
- tests/_templates/dhcpv4_post_bound_discover.sce-template.xml
- tests/_templates/dhcpv4_rebinding_retx_field.sce-template.xml
- tests/_templates/dhcpv4_renewing_retx_field.sce-template.xml
- tests/dhcpv4_client_reacquisition_03/dhcpv4_client_reacquisition_03.scxml
- tests/dhcpv4_client_reacquisition_04/dhcpv4_client_reacquisition_04.scxml
- tests/dhcpv4_client_reacquisition_07/dhcpv4_client_reacquisition_07.scxml



### §4.5. 4.5


**Intent**: TC8 §4.5 — auto-seeded TC8-internal sub-section (43 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.h
- dut/dut_service/linklocal_autoconf.cpp
- dut/dut_service/linklocal_autoconf.h
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/iface_enumeration.h
- include/tc8/protocol_frames/ipv4_frame.h
- include/tc8/rfc3927_constants.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.h
- src/dissect/packet_pipeline.h
- src/sce_integration/arp_captured.h
- src/sce_integration/cases/_ipv4_autoconf_traits_base.h
- src/sce_integration/cases/_ipv4_traits_base.h
- src/sce_integration/cases/someip_ets_122.h
- src/sce_integration/dhcpv4_pilot_common.h
- src/sce_integration/ipv4_linklocal_common.h
- src/stimulus/upper_tester_client.h
- tests/_templates/ipv4_linklocal_announce_field.sce-template.xml



### §4.5.6.1. 4.5.6.1


**Intent**: TC8 §4.5.6.1 — IPv4 Link-Local Autoconf — Introduction. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.cpp
- src/capture/bpf_filter.h
- src/sce_integration/arp_and_dhcpv4_captured.h
- src/sce_integration/arp_and_dhcpv4_expected.h
- src/sce_integration/arp_and_dhcpv4_pilot_common.h
- tests/ipv4_autoconf_intro_01/ipv4_autoconf_intro_01.scxml



### §4.5.6.2. 4.5.6.2


**Intent**: TC8 §4.5.6.2 — IPv4 Link-Local Autoconf — Address Selection / Probing / Configuration. 14 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/linklocal_autoconf.cpp
- dut/dut_service/linklocal_autoconf.h
- dut/env/smoke-test.sh
- include/tc8/rfc3927_constants.h
- include/tc8/upper_tester_protocol.h
- src/sce_integration/arp_captured.h
- src/sce_integration/arp_expectations.h
- src/sce_integration/arp_expected.h
- src/sce_integration/cases/ipv4_autoconf_network_partitions_01.h
- src/sce_integration/ipv4_linklocal_common.h
- src/sce_integration/test_case_traits.h
- src/sce_integration/test_runner.h
- src/stimulus/upper_tester_client.h
- tests/_templates/ipv4_linklocal_conflict_repick.sce-template.xml
- tests/_templates/ipv4_linklocal_probe_field.sce-template.xml
- tests/ipv4_autoconf_address_selection_01/ipv4_autoconf_address_selection_01.scxml
- tests/ipv4_autoconf_address_selection_01_neg/ipv4_autoconf_address_selection_01_neg.scxml
- tests/ipv4_autoconf_address_selection_03/ipv4_autoconf_address_selection_03.scxml
- tests/ipv4_autoconf_address_selection_05/ipv4_autoconf_address_selection_05.scxml
- tests/ipv4_autoconf_address_selection_05_neg/ipv4_autoconf_address_selection_05_neg.scxml
- tests/ipv4_autoconf_address_selection_06/ipv4_autoconf_address_selection_06.scxml
- tests/ipv4_autoconf_address_selection_06_neg/ipv4_autoconf_address_selection_06_neg.scxml
- tests/ipv4_autoconf_address_selection_07/ipv4_autoconf_address_selection_07.scxml
- tests/ipv4_autoconf_address_selection_07_neg/ipv4_autoconf_address_selection_07_neg.scxml
- tests/ipv4_autoconf_address_selection_08/ipv4_autoconf_address_selection_08.scxml
- tests/ipv4_autoconf_address_selection_08_neg/ipv4_autoconf_address_selection_08_neg.scxml
- tests/ipv4_autoconf_address_selection_09/ipv4_autoconf_address_selection_09.scxml
- tests/ipv4_autoconf_address_selection_10/ipv4_autoconf_address_selection_10.scxml
- tests/ipv4_autoconf_address_selection_10_neg/ipv4_autoconf_address_selection_10_neg.scxml
- tests/ipv4_autoconf_address_selection_11/ipv4_autoconf_address_selection_11.scxml
- tests/ipv4_autoconf_address_selection_12/ipv4_autoconf_address_selection_12.scxml
- tests/ipv4_autoconf_address_selection_13/ipv4_autoconf_address_selection_13.scxml
- tests/ipv4_autoconf_address_selection_14/ipv4_autoconf_address_selection_14.scxml
- tests/ipv4_autoconf_address_selection_15/ipv4_autoconf_address_selection_15.scxml
- tests/ipv4_autoconf_address_selection_16/ipv4_autoconf_address_selection_16.scxml
- tests/ipv4_autoconf_conflict_11/ipv4_autoconf_conflict_11.scxml



### §4.5.6.3. 4.5.6.3


**Intent**: TC8 §4.5.6.3 — IPv4 Link-Local Autoconf — Announcing. 6 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/linklocal_autoconf.cpp
- dut/dut_service/linklocal_autoconf.h
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- tests/_templates/ipv4_linklocal_announce_field.sce-template.xml
- tests/ipv4_autoconf_announcing_01/ipv4_autoconf_announcing_01.scxml
- tests/ipv4_autoconf_announcing_01_neg/ipv4_autoconf_announcing_01_neg.scxml
- tests/ipv4_autoconf_announcing_02/ipv4_autoconf_announcing_02.scxml
- tests/ipv4_autoconf_announcing_02_neg/ipv4_autoconf_announcing_02_neg.scxml
- tests/ipv4_autoconf_announcing_03/ipv4_autoconf_announcing_03.scxml
- tests/ipv4_autoconf_announcing_03_neg/ipv4_autoconf_announcing_03_neg.scxml
- tests/ipv4_autoconf_announcing_04/ipv4_autoconf_announcing_04.scxml
- tests/ipv4_autoconf_announcing_04_neg/ipv4_autoconf_announcing_04_neg.scxml
- tests/ipv4_autoconf_announcing_05/ipv4_autoconf_announcing_05.scxml
- tests/ipv4_autoconf_announcing_06/ipv4_autoconf_announcing_06.scxml



### §4.5.6.4. 4.5.6.4


**Intent**: TC8 §4.5.6.4 — IPv4 Link-Local Autoconf — Conflict Detection / Defense. 6 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/linklocal_autoconf.cpp
- dut/dut_service/linklocal_autoconf.h
- dut/env/smoke-test.sh
- src/sce_integration/cases/ipv4_autoconf_address_selection_16.h
- src/sce_integration/cases/ipv4_autoconf_network_partitions_01.h
- src/sce_integration/ipv4_linklocal_common.h
- tests/_templates/ipv4_linklocal_defender_cease.sce-template.xml
- tests/ipv4_autoconf_address_selection_16/ipv4_autoconf_address_selection_16.scxml
- tests/ipv4_autoconf_conflict_06/ipv4_autoconf_conflict_06.scxml
- tests/ipv4_autoconf_conflict_07/ipv4_autoconf_conflict_07.scxml
- tests/ipv4_autoconf_conflict_08/ipv4_autoconf_conflict_08.scxml
- tests/ipv4_autoconf_conflict_09/ipv4_autoconf_conflict_09.scxml
- tests/ipv4_autoconf_conflict_10/ipv4_autoconf_conflict_10.scxml
- tests/ipv4_autoconf_conflict_11/ipv4_autoconf_conflict_11.scxml



### §4.5.6.5. 4.5.6.5


**Intent**: TC8 §4.5.6.5 — IPv4 Link-Local Autoconf — Link-local Packets. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/ipv4_linklocal_common.h
- tests/ipv4_autoconf_linklocal_packets_04/ipv4_autoconf_linklocal_packets_04.scxml



### §4.5.6.6. 4.5.6.6


**Intent**: TC8 §4.5.6.6 — IPv4 Link-Local Autoconf — Network Partitions. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- tests/ipv4_autoconf_network_partitions_01/ipv4_autoconf_network_partitions_01.scxml



### §4.6. 4.6


**Intent**: TC8 §4.6 — auto-seeded TC8-internal sub-section (20 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/protocol_frames/udp_frame.h
- src/capture/bpf_filter.h
- src/dissect/packet_pipeline.h
- src/sce_integration/cases/_udp_traits_base.h
- src/sce_integration/cases/someip_ets_122.h
- src/sce_integration/cases/udp_fields_04.h
- src/sce_integration/udp_captured.h
- src/sce_integration/udp_pilot_common.h
- tests/_templates/udp_field_check.sce-template.xml
- tests/someip_ets_122/someip_ets_122.scxml



### §4.6.5.1. 4.6.5.1


**Intent**: TC8 §4.6.5.1 — UDP — Message Format. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/udp_messageformat_02/udp_messageformat_02.scxml



### §4.6.5.2. 4.6.5.2


**Intent**: TC8 §4.6.5.2 — UDP — Datagram Length. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/udp_datagramlength_01/udp_datagramlength_01.scxml



### §4.6.5.3. 4.6.5.3


**Intent**: TC8 §4.6.5.3 — UDP — Padding. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/udp_padding_02/udp_padding_02.scxml



### §4.6.5.4. 4.6.5.4


**Intent**: TC8 §4.6.5.4 — UDP — Fields. 15 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- src/dissect/packet_pipeline.cpp
- src/sce_integration/cases/udp_fields_12.h
- src/sce_integration/udp_captured.h
- src/sce_integration/udp_pilot_common.h
- src/stimulus/udp_datagram_builder.h
- tests/_templates/udp_field_check.sce-template.xml
- tests/udp_fields_01/udp_fields_01.scxml
- tests/udp_fields_02/udp_fields_02.scxml
- tests/udp_fields_03/udp_fields_03.scxml
- tests/udp_fields_04/udp_fields_04.scxml
- tests/udp_fields_05/udp_fields_05.scxml
- tests/udp_fields_06/udp_fields_06.scxml
- tests/udp_fields_07/udp_fields_07.scxml
- tests/udp_fields_08/udp_fields_08.scxml
- tests/udp_fields_09/udp_fields_09.scxml
- tests/udp_fields_10/udp_fields_10.scxml
- tests/udp_fields_12/udp_fields_12.scxml
- tests/udp_fields_13/udp_fields_13.scxml
- tests/udp_fields_14/udp_fields_14.scxml
- tests/udp_fields_15/udp_fields_15.scxml
- tests/udp_fields_16/udp_fields_16.scxml



### §4.6.5.5. 4.6.5.5


**Intent**: TC8 §4.6.5.5 — UDP — User Interface. 8 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/setup-netns.sh
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/udp_user_interface_07.h
- src/sce_integration/cases/udp_user_interface_08.h
- src/sce_integration/ipv4_expectations.h
- src/sce_integration/ipv4_expected.h
- src/sce_integration/udp_captured.h
- src/sce_integration/udp_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/_templates/udp_ut_received_check.sce-template.xml
- tests/udp_user_interface_01/udp_user_interface_01.scxml
- tests/udp_user_interface_02/udp_user_interface_02.scxml
- tests/udp_user_interface_03/udp_user_interface_03.scxml
- tests/udp_user_interface_04/udp_user_interface_04.scxml
- tests/udp_user_interface_05/udp_user_interface_05.scxml
- tests/udp_user_interface_06/udp_user_interface_06.scxml
- tests/udp_user_interface_07/udp_user_interface_07.scxml
- tests/udp_user_interface_08/udp_user_interface_08.scxml



### §4.6.5.6. 4.6.5.6


**Intent**: TC8 §4.6.5.6 — UDP — Introduction. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- src/sce_integration/cases/udp_introduction_01.h
- src/sce_integration/cases/udp_introduction_02.h
- tests/_templates/udp_no_listen.sce-template.xml
- tests/udp_introduction_01/udp_introduction_01.scxml
- tests/udp_introduction_02/udp_introduction_02.scxml
- tests/udp_introduction_03/udp_introduction_03.scxml



### §4.6.5.7. 4.6.5.7


**Intent**: TC8 §4.6.5.7 — UDP — Invalid Addresses. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/sce_integration/udp_pilot_common.h
- tests/udp_invalid_addresses_01/udp_invalid_addresses_01.scxml
- tests/udp_invalid_addresses_02/udp_invalid_addresses_02.scxml



### §4.7. 4.7


**Intent**: TC8 §4.7 — auto-seeded TC8-internal sub-section (43 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.h
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/protocol_frames/dhcpv4_frame.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.h
- src/cli/expect_parser.h
- src/dissect/packet_pipeline.cpp
- src/dissect/packet_pipeline.h
- src/sce_integration/arp_and_dhcpv4_pilot_common.h
- src/sce_integration/cases/_dhcpv4_traits_base.h
- src/sce_integration/cases/dhcpv4_client_summary_02.h
- src/sce_integration/cases/ipv4_autoconf_intro_01.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_default_endpoints.h
- src/sce_integration/dhcpv4_expectations.h
- src/sce_integration/dhcpv4_expected.h
- src/sce_integration/dhcpv4_pilot_common.h
- src/sce_integration/dhcpv4_server_stimulus.h
- src/stimulus/dhcpv4_frame_builder.h
- src/stimulus/upper_tester_client.h
- src/wire/ip_checksum.h
- tests/_templates/dhcpv4_request_field.sce-template.xml
- tests/dhcpv4_client_allocating_05/dhcpv4_client_allocating_05.scxml



### §4.7.1. 4.7.1


**Intent**: TC8 §4.7.1 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/stimulus/someip_rpc_builder.h



### §4.7.2. 4.7.2


**Intent**: TC8 §4.7.2 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/stimulus/someip_rpc_builder.h



### §4.7.3. 4.7.3


**Intent**: TC8 §4.7.3 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/dhcpv4_client_summary_02.h



### §4.7.4. 4.7.4


**Intent**: TC8 §4.7.4 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someip_ets_059.h
- src/sce_integration/cases/someip_ets_075.h



### §4.7.5. 4.7.5


**Intent**: TC8 §4.7.5 — auto-seeded TC8-internal sub-section (5 code citations at baseline).









**Implementations**:
- src/sce_integration/dhcpv4_pilot_common.h
- tests/dhcpv4_client_reacquisition_03/dhcpv4_client_reacquisition_03.scxml
- tests/dhcpv4_client_reacquisition_04/dhcpv4_client_reacquisition_04.scxml
- tests/dhcpv4_client_reacquisition_05/dhcpv4_client_reacquisition_05.scxml
- tests/dhcpv4_client_reacquisition_06/dhcpv4_client_reacquisition_06.scxml



### §4.7.6.1. 4.7.6.1


**Intent**: TC8 §4.7.6.1 — DHCPv4 Client — Summary. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_default_endpoints.h
- src/sce_integration/dhcpv4_expected.h
- src/sce_integration/dhcpv4_server_stimulus.h
- src/stimulus/dhcpv4_frame_builder.cpp
- src/stimulus/dhcpv4_frame_builder.h
- tests/dhcpv4_client_summary_01/dhcpv4_client_summary_01.scxml
- tests/dhcpv4_client_summary_02/dhcpv4_client_summary_02.scxml
- tests/dhcpv4_client_summary_03/dhcpv4_client_summary_03.scxml
- tests/dhcpv4_client_summary_04/dhcpv4_client_summary_04.scxml



### §4.7.6.2. 4.7.6.2


**Intent**: TC8 §4.7.6.2 — DHCPv4 Client — Protocol. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/dhcpv4_captured.h
- tests/dhcpv4_client_protocol_01/dhcpv4_client_protocol_01.scxml
- tests/dhcpv4_client_protocol_02/dhcpv4_client_protocol_02.scxml
- tests/dhcpv4_client_protocol_03/dhcpv4_client_protocol_03.scxml



### §4.7.6.3. 4.7.6.3


**Intent**: TC8 §4.7.6.3 — DHCPv4 Client — Allocating. 9 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- dut/env/smoke-test.sh
- src/sce_integration/arp_and_dhcpv4_pilot_common.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_default_endpoints.h
- src/sce_integration/dhcpv4_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/_templates/dhcpv4_post_bound_discover.sce-template.xml
- tests/_templates/dhcpv4_post_decline_discover.sce-template.xml
- tests/_templates/dhcpv4_renewing_retx_field.sce-template.xml
- tests/dhcpv4_client_allocating_01/dhcpv4_client_allocating_01.scxml
- tests/dhcpv4_client_allocating_03/dhcpv4_client_allocating_03.scxml
- tests/dhcpv4_client_allocating_04/dhcpv4_client_allocating_04.scxml
- tests/dhcpv4_client_allocating_05/dhcpv4_client_allocating_05.scxml
- tests/dhcpv4_client_allocating_06/dhcpv4_client_allocating_06.scxml
- tests/dhcpv4_client_allocating_07/dhcpv4_client_allocating_07.scxml
- tests/dhcpv4_client_allocating_08/dhcpv4_client_allocating_08.scxml
- tests/dhcpv4_client_allocating_09/dhcpv4_client_allocating_09.scxml
- tests/dhcpv4_client_allocating_10/dhcpv4_client_allocating_10.scxml



### §4.7.6.4. 4.7.6.4


**Intent**: TC8 §4.7.6.4 — DHCPv4 Client — Parameters. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/dhcpv4_client_parameters_04/dhcpv4_client_parameters_04.scxml



### §4.7.6.5. 4.7.6.5


**Intent**: TC8 §4.7.6.5 — DHCPv4 Client — Usage. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/setup-netns.sh
- dut/env/smoke-test.sh
- include/tc8/iface_enumeration.h
- include/tc8/upper_tester_protocol.h
- src/cli/test_command.cpp
- src/cli/test_command.h
- src/sce_integration/dhcpv4_captured.h
- src/stimulus/upper_tester_client.h
- tests/dhcpv4_client_usage_01/dhcpv4_client_usage_01.scxml



### §4.7.6.6. 4.7.6.6


**Intent**: TC8 §4.7.6.6 — DHCPv4 Client — Constructing Messages / Request. 17 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/dhcpv4_client_constructing_messages_01/dhcpv4_client_constructing_messages_01.scxml
- tests/dhcpv4_client_constructing_messages_02/dhcpv4_client_constructing_messages_02.scxml
- tests/dhcpv4_client_constructing_messages_03/dhcpv4_client_constructing_messages_03.scxml
- tests/dhcpv4_client_constructing_messages_04/dhcpv4_client_constructing_messages_04.scxml
- tests/dhcpv4_client_constructing_messages_05/dhcpv4_client_constructing_messages_05.scxml
- tests/dhcpv4_client_constructing_messages_06/dhcpv4_client_constructing_messages_06.scxml
- tests/dhcpv4_client_constructing_messages_12/dhcpv4_client_constructing_messages_12.scxml
- tests/dhcpv4_client_constructing_messages_13/dhcpv4_client_constructing_messages_13.scxml



### §4.7.6.7. 4.7.6.7


**Intent**: TC8 §4.7.6.7 — DHCPv4 Client — Initialization Allocation. 9 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- src/capture/bpf_filter.cpp
- src/capture/bpf_filter.h
- src/sce_integration/cases/dhcpv4_router_option_egress_common.h
- src/sce_integration/cases/ipv4_autoconf_intro_01.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_default_endpoints.h
- src/sce_integration/dhcpv4_server_stimulus.h
- src/sce_integration/udp_and_dhcpv4_captured.h
- src/sce_integration/udp_and_dhcpv4_expected.h
- src/sce_integration/udp_and_dhcpv4_pilot_common.h
- src/sce_integration/udp_captured.h
- src/stimulus/dhcpv4_frame_builder.cpp
- src/stimulus/dhcpv4_frame_builder.h
- src/stimulus/upper_tester_client.h
- tests/_templates/dhcpv4_router_option_egress.sce-template.xml
- tests/dhcpv4_client_constructing_messages_02/dhcpv4_client_constructing_messages_02.scxml



### §4.7.6.8. 4.7.6.8


**Intent**: TC8 §4.7.6.8 — DHCPv4 Client — Reacquisition. 8 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dhcpv4_client.h
- dut/env/smoke-test.sh
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_default_endpoints.h
- src/sce_integration/dhcpv4_pilot_common.h
- tests/_templates/dhcpv4_lease_release_no_udp.sce-template.xml
- tests/_templates/dhcpv4_post_bound_discover.sce-template.xml
- tests/_templates/dhcpv4_rebinding_request_field.sce-template.xml
- tests/_templates/dhcpv4_rebinding_retx_field.sce-template.xml
- tests/_templates/dhcpv4_renewing_request_field.sce-template.xml
- tests/_templates/dhcpv4_renewing_retx_field.sce-template.xml
- tests/dhcpv4_client_constructing_messages_02/dhcpv4_client_constructing_messages_02.scxml
- tests/dhcpv4_client_reacquisition_01/dhcpv4_client_reacquisition_01.scxml
- tests/dhcpv4_client_reacquisition_02/dhcpv4_client_reacquisition_02.scxml
- tests/dhcpv4_client_reacquisition_03/dhcpv4_client_reacquisition_03.scxml
- tests/dhcpv4_client_reacquisition_04/dhcpv4_client_reacquisition_04.scxml
- tests/dhcpv4_client_reacquisition_05/dhcpv4_client_reacquisition_05.scxml
- tests/dhcpv4_client_reacquisition_06/dhcpv4_client_reacquisition_06.scxml
- tests/dhcpv4_client_reacquisition_07/dhcpv4_client_reacquisition_07.scxml
- tests/dhcpv4_client_reacquisition_08/dhcpv4_client_reacquisition_08.scxml
- tests/dhcpv4_client_request_01/dhcpv4_client_request_01.scxml
- tests/dhcpv4_client_request_02/dhcpv4_client_request_02.scxml
- tests/dhcpv4_client_request_06/dhcpv4_client_request_06.scxml
- tests/dhcpv4_client_request_07/dhcpv4_client_request_07.scxml
- tests/dhcpv4_client_request_08/dhcpv4_client_request_08.scxml
- tests/dhcpv4_client_request_09/dhcpv4_client_request_09.scxml
- tests/dhcpv4_client_request_10/dhcpv4_client_request_10.scxml
- tests/dhcpv4_client_request_11/dhcpv4_client_request_11.scxml
- tests/dhcpv4_client_request_12/dhcpv4_client_request_12.scxml



### §4.7.6.9. 4.7.6.9


**Intent**: TC8 §4.7.6.9 — auto-seeded TC8-internal sub-section (34 code citations at baseline).









**Implementations**:
- dut/dut_service/dhcpv4_client.cpp
- dut/dut_service/dhcpv4_client.h
- dut/env/smoke-test.sh
- src/sce_integration/arp_captured.h
- src/sce_integration/cases/dhcpv4_client_initialization_allocation_01.h
- src/sce_integration/dhcpv4_captured.h
- src/sce_integration/dhcpv4_pilot_common.h
- src/sce_integration/dhcpv4_server_stimulus.h
- src/stimulus/upper_tester_client.h
- tests/dhcpv4_client_initialization_allocation_01/dhcpv4_client_initialization_allocation_01.scxml
- tests/dhcpv4_client_initialization_allocation_02/dhcpv4_client_initialization_allocation_02.scxml
- tests/dhcpv4_client_initialization_allocation_03/dhcpv4_client_initialization_allocation_03.scxml
- tests/dhcpv4_client_initialization_allocation_04/dhcpv4_client_initialization_allocation_04.scxml
- tests/dhcpv4_client_initialization_allocation_05/dhcpv4_client_initialization_allocation_05.scxml
- tests/dhcpv4_client_initialization_allocation_06/dhcpv4_client_initialization_allocation_06.scxml
- tests/dhcpv4_client_initialization_allocation_08/dhcpv4_client_initialization_allocation_08.scxml
- tests/dhcpv4_client_initialization_allocation_09/dhcpv4_client_initialization_allocation_09.scxml
- tests/dhcpv4_client_initialization_allocation_10/dhcpv4_client_initialization_allocation_10.scxml



### §4.8. 4.8


**Intent**: TC8 §4.8 — auto-seeded TC8-internal sub-section (36 code citations at baseline).









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/iface_enumeration.h
- include/tc8/protocol_frames/tcp_frame.h
- include/tc8/upper_tester_protocol.h
- src/capture/bpf_filter.h
- src/capture/pcap_source.cpp
- src/dissect/packet_pipeline.cpp
- src/dissect/packet_pipeline.h
- src/sce_integration/cases/_tcp_traits_base.h
- src/sce_integration/cases/tcp_flags_processing_06.h
- src/sce_integration/cases/tcp_flags_processing_07.h
- src/sce_integration/cases/tcp_flags_processing_09.h
- src/sce_integration/cases/tcp_header_04.h
- src/sce_integration/cases/tcp_retransmission_to_06.h
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/tcp_segment_builder.h
- tests/_templates/tcp_time_wait_dual_phase_otw_probe.sce-template.xml
- tests/tcp_checksum_04/tcp_checksum_04.scxml
- tests/tcp_flags_processing_06/tcp_flags_processing_06.scxml
- tests/tcp_header_04/tcp_header_04.scxml
- tests/tcp_probing_windows_02/tcp_probing_windows_02.scxml
- src/capture/bpf_filter.cpp



### §4.8.5. 4.8.5


**Intent**: TC8 §4.8.5 — auto-seeded TC8-internal sub-section (24 code citations at baseline).









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/ipv4_fragments_05.h
- src/sce_integration/tcp_pilot_common.h
- src/sce_integration/udp_captured.h
- src/stimulus/upper_tester_client.h
- tests/_templates/ipv4_udp_ut_presence.sce-template.xml
- tests/_templates/udp_field_check.sce-template.xml
- tests/ipv4_addressing_01/ipv4_addressing_01.scxml
- tests/ipv4_addressing_02/ipv4_addressing_02.scxml
- tests/ipv4_fragments_05/ipv4_fragments_05.scxml
- tests/tcp_basics_01/tcp_basics_01.scxml
- tests/tcp_basics_02/tcp_basics_02.scxml
- tests/tcp_basics_03/tcp_basics_03.scxml
- tests/tcp_basics_06/tcp_basics_06.scxml
- tests/udp_user_interface_01/udp_user_interface_01.scxml
- src/capture/bpf_filter.cpp



### §4.8.6. 4.8.6


**Intent**: TC8 §4.8.6 — auto-seeded TC8-internal sub-section (27 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/cases/tcp_header_04.h
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/tcp_segment_builder.cpp
- src/stimulus/tcp_segment_builder.h
- tests/tcp_header_01/tcp_header_01.scxml
- tests/tcp_header_02/tcp_header_02.scxml
- tests/tcp_mss_options_11/tcp_mss_options_11.scxml



### §4.8.6.1. 4.8.6.1


**Intent**: TC8 §4.8.6.1 — TCP — Basics. 15 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/dissect/packet_pipeline.cpp
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/tcp_segment_builder.h
- src/stimulus/upper_tester_client.h
- tests/_templates/tcp_time_wait_4state.sce-template.xml
- tests/tcp_basics_01/tcp_basics_01.scxml
- tests/tcp_basics_02/tcp_basics_02.scxml
- tests/tcp_basics_03/tcp_basics_03.scxml
- tests/tcp_basics_04/tcp_basics_04.scxml
- tests/tcp_basics_05/tcp_basics_05.scxml
- tests/tcp_basics_06/tcp_basics_06.scxml
- tests/tcp_basics_07/tcp_basics_07.scxml
- tests/tcp_basics_08/tcp_basics_08.scxml
- tests/tcp_basics_09/tcp_basics_09.scxml
- tests/tcp_basics_10/tcp_basics_10.scxml
- tests/tcp_basics_11/tcp_basics_11.scxml
- tests/tcp_basics_12/tcp_basics_12.scxml
- tests/tcp_basics_13/tcp_basics_13.scxml
- tests/tcp_basics_14/tcp_basics_14.scxml
- tests/tcp_basics_17/tcp_basics_17.scxml



### §4.8.6.10. 4.8.6.10


**Intent**: TC8 §4.8.6.10 — TCP — Out of Order. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_out_of_order_01/tcp_out_of_order_01.scxml
- tests/tcp_out_of_order_02/tcp_out_of_order_02.scxml
- tests/tcp_out_of_order_03/tcp_out_of_order_03.scxml
- tests/tcp_out_of_order_05/tcp_out_of_order_05.scxml



### §4.8.6.11. 4.8.6.11


**Intent**: TC8 §4.8.6.11 — TCP — Retransmission Timeout. 6 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/tcp_frame.h
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/tcp_retransmission_to_08.h
- src/sce_integration/cases/tcp_retransmission_to_09.h
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/tcp_probing_windows_06/tcp_probing_windows_06.scxml
- tests/tcp_retransmission_to_03/tcp_retransmission_to_03.scxml
- tests/tcp_retransmission_to_04/tcp_retransmission_to_04.scxml
- tests/tcp_retransmission_to_05/tcp_retransmission_to_05.scxml
- tests/tcp_retransmission_to_06/tcp_retransmission_to_06.scxml
- tests/tcp_retransmission_to_08/tcp_retransmission_to_08.scxml
- tests/tcp_retransmission_to_09/tcp_retransmission_to_09.scxml



### §4.8.6.12. 4.8.6.12


**Intent**: TC8 §4.8.6.12 — TCP — Probing Windows. 5 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/tcp_frame.h
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_probing_windows_02/tcp_probing_windows_02.scxml
- tests/tcp_probing_windows_03/tcp_probing_windows_03.scxml
- tests/tcp_probing_windows_04/tcp_probing_windows_04.scxml
- tests/tcp_probing_windows_05/tcp_probing_windows_05.scxml
- tests/tcp_probing_windows_06/tcp_probing_windows_06.scxml



### §4.8.6.13. 4.8.6.13


**Intent**: TC8 §4.8.6.13 — TCP — Nagle. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_nagle_02/tcp_nagle_02.scxml
- tests/tcp_nagle_03/tcp_nagle_03.scxml



### §4.8.6.14. 4.8.6.14


**Intent**: TC8 §4.8.6.14 — TCP — Urgent Pointer. 1 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/tcp_urgent_ptr_04/tcp_urgent_ptr_04.scxml



### §4.8.6.15. 4.8.6.15


**Intent**: TC8 §4.8.6.15 — TCP — Connection Establishment. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_connection_estab_01/tcp_connection_estab_01.scxml
- tests/tcp_connection_estab_02/tcp_connection_estab_02.scxml
- tests/tcp_connection_estab_03/tcp_connection_estab_03.scxml
- tests/tcp_connection_estab_07/tcp_connection_estab_07.scxml



### §4.8.6.16. 4.8.6.16


**Intent**: TC8 §4.8.6.16 — TCP — Header. 9 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/tcp_header_01/tcp_header_01.scxml
- tests/tcp_header_02/tcp_header_02.scxml
- tests/tcp_header_04/tcp_header_04.scxml
- tests/tcp_header_05/tcp_header_05.scxml
- tests/tcp_header_06/tcp_header_06.scxml
- tests/tcp_header_07/tcp_header_07.scxml
- tests/tcp_header_08/tcp_header_08.scxml
- tests/tcp_header_09/tcp_header_09.scxml
- tests/tcp_header_11/tcp_header_11.scxml



### §4.8.6.17. 4.8.6.17


**Intent**: TC8 §4.8.6.17 — TCP — Sequence. 5 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_sequence_01/tcp_sequence_01.scxml
- tests/tcp_sequence_02/tcp_sequence_02.scxml
- tests/tcp_sequence_03/tcp_sequence_03.scxml
- tests/tcp_sequence_04/tcp_sequence_04.scxml
- tests/tcp_sequence_05/tcp_sequence_05.scxml



### §4.8.6.18. 4.8.6.18


**Intent**: TC8 §4.8.6.18 — TCP — Acknowledgement. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_acknowledgement_02/tcp_acknowledgement_02.scxml
- tests/tcp_acknowledgement_03/tcp_acknowledgement_03.scxml
- tests/tcp_acknowledgement_04/tcp_acknowledgement_04.scxml



### §4.8.6.19. 4.8.6.19


**Intent**: TC8 §4.8.6.19 — TCP — Control Flags. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_control_flags_05/tcp_control_flags_05.scxml
- tests/tcp_control_flags_08/tcp_control_flags_08.scxml



### §4.8.6.2. 4.8.6.2


**Intent**: TC8 §4.8.6.2 — TCP — Checksum. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/setup-netns.sh
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/tcp_frame.h
- include/tc8/upper_tester_protocol.h
- src/dissect/packet_pipeline.cpp
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/tcp_segment_builder.cpp
- src/stimulus/tcp_segment_builder.h
- src/stimulus/upper_tester_client.h
- tests/tcp_checksum_01/tcp_checksum_01.scxml
- tests/tcp_checksum_02/tcp_checksum_02.scxml
- tests/tcp_checksum_03/tcp_checksum_03.scxml
- tests/tcp_checksum_04/tcp_checksum_04.scxml
- tests/tcp_unacceptable_06/tcp_unacceptable_06.scxml



### §4.8.6.3. 4.8.6.3


**Intent**: TC8 §4.8.6.3 — TCP — Unacceptable Segments. 14 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_unacceptable_01/tcp_unacceptable_01.scxml
- tests/tcp_unacceptable_02/tcp_unacceptable_02.scxml
- tests/tcp_unacceptable_03/tcp_unacceptable_03.scxml
- tests/tcp_unacceptable_04/tcp_unacceptable_04.scxml
- tests/tcp_unacceptable_05/tcp_unacceptable_05.scxml
- tests/tcp_unacceptable_06/tcp_unacceptable_06.scxml
- tests/tcp_unacceptable_07/tcp_unacceptable_07.scxml
- tests/tcp_unacceptable_08/tcp_unacceptable_08.scxml
- tests/tcp_unacceptable_09/tcp_unacceptable_09.scxml
- tests/tcp_unacceptable_10/tcp_unacceptable_10.scxml
- tests/tcp_unacceptable_11/tcp_unacceptable_11.scxml
- tests/tcp_unacceptable_12/tcp_unacceptable_12.scxml
- tests/tcp_unacceptable_13/tcp_unacceptable_13.scxml
- tests/tcp_unacceptable_14/tcp_unacceptable_14.scxml



### §4.8.6.4. 4.8.6.4


**Intent**: TC8 §4.8.6.4 — TCP — Call Receive. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_captured.h
- tests/tcp_call_receive_04/tcp_call_receive_04.scxml
- tests/tcp_call_receive_05/tcp_call_receive_05.scxml



### §4.8.6.5. 4.8.6.5


**Intent**: TC8 §4.8.6.5 — TCP — Call Abort. 2 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/tcp_call_abort_02/tcp_call_abort_02.scxml
- tests/tcp_call_abort_03/tcp_call_abort_03.scxml



### §4.8.6.6. 4.8.6.6


**Intent**: TC8 §4.8.6.6 — TCP — Invalid Flag Combinations. 15 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/cases/tcp_basics_13.h
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/sce_integration/test_case_traits.h
- tests/tcp_flags_invalid_01/tcp_flags_invalid_01.scxml
- tests/tcp_flags_invalid_02/tcp_flags_invalid_02.scxml
- tests/tcp_flags_invalid_03/tcp_flags_invalid_03.scxml
- tests/tcp_flags_invalid_04/tcp_flags_invalid_04.scxml
- tests/tcp_flags_invalid_05/tcp_flags_invalid_05.scxml
- tests/tcp_flags_invalid_06/tcp_flags_invalid_06.scxml
- tests/tcp_flags_invalid_07/tcp_flags_invalid_07.scxml
- tests/tcp_flags_invalid_08/tcp_flags_invalid_08.scxml
- tests/tcp_flags_invalid_09/tcp_flags_invalid_09.scxml
- tests/tcp_flags_invalid_10/tcp_flags_invalid_10.scxml
- tests/tcp_flags_invalid_11/tcp_flags_invalid_11.scxml
- tests/tcp_flags_invalid_12/tcp_flags_invalid_12.scxml
- tests/tcp_flags_invalid_13/tcp_flags_invalid_13.scxml
- tests/tcp_flags_invalid_14/tcp_flags_invalid_14.scxml
- tests/tcp_flags_invalid_15/tcp_flags_invalid_15.scxml



### §4.8.6.7. 4.8.6.7


**Intent**: TC8 §4.8.6.7 — TCP — Flag Processing. 8 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/tcp_pilot_common.h
- tests/tcp_call_abort_02/tcp_call_abort_02.scxml
- tests/tcp_flags_processing_02/tcp_flags_processing_02.scxml
- tests/tcp_flags_processing_05/tcp_flags_processing_05.scxml
- tests/tcp_flags_processing_06/tcp_flags_processing_06.scxml
- tests/tcp_flags_processing_07/tcp_flags_processing_07.scxml
- tests/tcp_flags_processing_08/tcp_flags_processing_08.scxml
- tests/tcp_flags_processing_09/tcp_flags_processing_09.scxml
- tests/tcp_flags_processing_10/tcp_flags_processing_10.scxml
- tests/tcp_flags_processing_11/tcp_flags_processing_11.scxml



### §4.8.6.8. 4.8.6.8


**Intent**: TC8 §4.8.6.8 — TCP — Closing. 6 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.cpp
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/tcp_closing_03.h
- src/sce_integration/cases/tcp_closing_06.h
- src/sce_integration/cases/tcp_closing_07.h
- src/sce_integration/cases/tcp_closing_09.h
- src/sce_integration/cases/tcp_closing_13.h
- src/sce_integration/tcp_captured.h
- src/stimulus/upper_tester_client.h
- tests/tcp_call_abort_02/tcp_call_abort_02.scxml
- tests/tcp_closing_03/tcp_closing_03.scxml
- tests/tcp_closing_06/tcp_closing_06.scxml
- tests/tcp_closing_07/tcp_closing_07.scxml
- tests/tcp_closing_08/tcp_closing_08.scxml
- tests/tcp_closing_09/tcp_closing_09.scxml
- tests/tcp_closing_13/tcp_closing_13.scxml



### §4.8.6.9. 4.8.6.9


**Intent**: TC8 §4.8.6.9 — TCP — MSS Options. 9 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/upper_tester_server.h
- dut/env/smoke-test.sh
- include/tc8/upper_tester_protocol.h
- src/sce_integration/tcp_captured.h
- src/sce_integration/tcp_pilot_common.h
- src/stimulus/upper_tester_client.h
- tests/tcp_mss_options_01/tcp_mss_options_01.scxml
- tests/tcp_mss_options_02/tcp_mss_options_02.scxml
- tests/tcp_mss_options_03/tcp_mss_options_03.scxml
- tests/tcp_mss_options_05/tcp_mss_options_05.scxml
- tests/tcp_mss_options_06/tcp_mss_options_06.scxml
- tests/tcp_mss_options_09/tcp_mss_options_09.scxml
- tests/tcp_mss_options_10/tcp_mss_options_10.scxml
- tests/tcp_mss_options_11/tcp_mss_options_11.scxml
- tests/tcp_mss_options_12/tcp_mss_options_12.scxml



### §5.1. 5.1


**Intent**: TC8 §5.1 — auto-seeded TC8-internal sub-section (28 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- include/tc8/bpf_group.h
- include/tc8/captured_event.h
- include/tc8/protocol_frames/someip_frame.h
- src/capture/bpf_filter.cpp
- src/capture/bpf_filter.h
- src/cli/test_command.h
- src/dissect/packet_pipeline.h
- src/sce_integration/arp_expected.h
- src/sce_integration/icmpv4_expected.h
- src/sce_integration/someip_captured.h
- src/sce_integration/someip_expectations.h
- src/sce_integration/someip_expected.h
- src/sce_integration/test_runner.h
- src/stimulus/someip_sd_builder.h
- tests/arp_08/arp_08.scxml
- tests/arp_09/arp_09.scxml
- tests/arp_10/arp_10.scxml
- tests/arp_11/arp_11.scxml
- tests/arp_12/arp_12.scxml
- tests/someipsrv_sd_behavior_01/someipsrv_sd_behavior_01.scxml
- tests/someipsrv_sd_behavior_02/someipsrv_sd_behavior_02.scxml



### §5.1.2.1. 5.1.2.1


**Intent**: TC8 §5.1.2.1 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- include/tc8/test_defaults.h



### §5.1.2.3. 5.1.2.3


**Intent**: TC8 §5.1.2.3 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- dut/dut_service/client_mode.cpp
- include/tc8/dut_config.h
- include/tc8/test_defaults.h



### §5.1.4. 5.1.4


**Intent**: TC8 §5.1.4 — auto-seeded TC8-internal sub-section (22 code citations at baseline).









**Implementations**:
- dut/ets/ets.fdepl
- dut/ets/ets.fidl
- include/tc8/ets_spec.h
- include/tc8/protocol_frames/someip_frame.h
- src/sce_integration/cases/someip_ets_076.h
- src/sce_integration/cases/someip_ets_099.h
- src/sce_integration/cases/someip_ets_103.h
- src/sce_integration/cases/someip_ets_166.h
- tests/someip_ets_076/someip_ets_076.scxml



### §5.1.4.2.1. 5.1.4.2.1


**Intent**: TC8 §5.1.4.2.1 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- dut/ets/ets.fidl
- src/sce_integration/cases/someip_ets_008.h
- tests/someip_ets_008/someip_ets_008.scxml



### §5.1.4.3.1. 5.1.4.3.1


**Intent**: TC8 §5.1.4.3.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- dut/dut_service/ets_impl.h
- dut/ets/ets.fidl



### §5.1.4.3.2. 5.1.4.3.2


**Intent**: TC8 §5.1.4.3.2 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- dut/dut_service/ets_impl.h
- dut/ets/ets.fidl
- tests/someip_ets_089/someip_ets_089.scxml



### §5.1.4.3.3. 5.1.4.3.3


**Intent**: TC8 §5.1.4.3.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- dut/dut_service/client_mode.h
- dut/ets/ets.fidl



### §5.1.4.4.1. 5.1.4.4.1


**Intent**: TC8 §5.1.4.4.1 — auto-seeded TC8-internal sub-section (1 code citations at baseline).









**Implementations**:
- dut/dut_service/ets_impl.h



### §5.1.5. 5.1.5


**Intent**: TC8 §5.1.5 — auto-seeded TC8-internal sub-section (13 code citations at baseline).









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/dut_service/ets_impl_2.h
- dut/env/smoke-test.sh
- dut/ets/CMakeLists.txt
- dut/ets/ets2.fidl
- src/sce_integration/cases/_someipsrv_traits_base.h
- src/sce_integration/cases/someipsrv_sd_message_01.h
- tests/_templates/someipsrv_sd_field_check.sce-template.xml
- tests/someipsrv_format_27/someipsrv_format_27.scxml



### §5.1.5.1. 5.1.5.1


**Intent**: TC8 §5.1.5.1 — SOME/IP Server — Message Format. 27 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/stimulus/someip_rpc_builder.h



### §5.1.5.1.1. 5.1.5.1.1


**Intent**: TC8 §5.1.5.1.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_01.h
- tests/someipsrv_format_01/someipsrv_format_01.scxml



### §5.1.5.1.10. 5.1.5.1.10


**Intent**: TC8 §5.1.5.1.10 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_10.h
- tests/someipsrv_format_10/someipsrv_format_10.scxml



### §5.1.5.1.11. 5.1.5.1.11


**Intent**: TC8 §5.1.5.1.11 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_11.h
- tests/someipsrv_format_11/someipsrv_format_11.scxml



### §5.1.5.1.12. 5.1.5.1.12


**Intent**: TC8 §5.1.5.1.12 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_12.h
- tests/someipsrv_format_12/someipsrv_format_12.scxml



### §5.1.5.1.13. 5.1.5.1.13


**Intent**: TC8 §5.1.5.1.13 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_13.h
- tests/someipsrv_format_13/someipsrv_format_13.scxml



### §5.1.5.1.14. 5.1.5.1.14


**Intent**: TC8 §5.1.5.1.14 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_14.h
- tests/someipsrv_format_14/someipsrv_format_14.scxml



### §5.1.5.1.15. 5.1.5.1.15


**Intent**: TC8 §5.1.5.1.15 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_15.h
- tests/someipsrv_format_15/someipsrv_format_15.scxml



### §5.1.5.1.16. 5.1.5.1.16


**Intent**: TC8 §5.1.5.1.16 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_16.h
- tests/someipsrv_format_16/someipsrv_format_16.scxml



### §5.1.5.1.17. 5.1.5.1.17


**Intent**: TC8 §5.1.5.1.17 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_17.h
- tests/someipsrv_format_17/someipsrv_format_17.scxml



### §5.1.5.1.18. 5.1.5.1.18


**Intent**: TC8 §5.1.5.1.18 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_18.h
- tests/someipsrv_format_18/someipsrv_format_18.scxml



### §5.1.5.1.19. 5.1.5.1.19


**Intent**: TC8 §5.1.5.1.19 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_19.h
- tests/someipsrv_format_19/someipsrv_format_19.scxml



### §5.1.5.1.2. 5.1.5.1.2


**Intent**: TC8 §5.1.5.1.2 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_02.h
- tests/someipsrv_format_02/someipsrv_format_02.scxml



### §5.1.5.1.20. 5.1.5.1.20


**Intent**: TC8 §5.1.5.1.20 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_20.h
- tests/someipsrv_format_20/someipsrv_format_20.scxml



### §5.1.5.1.21. 5.1.5.1.21


**Intent**: TC8 §5.1.5.1.21 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_21.h
- tests/someipsrv_format_21/someipsrv_format_21.scxml



### §5.1.5.1.23. 5.1.5.1.23


**Intent**: TC8 §5.1.5.1.23 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_23.h
- tests/someipsrv_format_23/someipsrv_format_23.scxml



### §5.1.5.1.24. 5.1.5.1.24


**Intent**: TC8 §5.1.5.1.24 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_24.h
- tests/someipsrv_format_24/someipsrv_format_24.scxml



### §5.1.5.1.25. 5.1.5.1.25


**Intent**: TC8 §5.1.5.1.25 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_25.h
- tests/someipsrv_format_25/someipsrv_format_25.scxml



### §5.1.5.1.26. 5.1.5.1.26


**Intent**: TC8 §5.1.5.1.26 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_26.h
- tests/someipsrv_format_26/someipsrv_format_26.scxml



### §5.1.5.1.27. 5.1.5.1.27


**Intent**: TC8 §5.1.5.1.27 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_27.h
- tests/someipsrv_format_27/someipsrv_format_27.scxml



### §5.1.5.1.28. 5.1.5.1.28


**Intent**: TC8 §5.1.5.1.28 — auto-seeded TC8-internal sub-section (4 code citations at baseline).









**Implementations**:
- dut/env/smoke-test.sh
- src/sce_integration/cases/someipsrv_format_28.h
- tests/someipsrv_format_28/someipsrv_format_28.scxml



### §5.1.5.1.3. 5.1.5.1.3


**Intent**: TC8 §5.1.5.1.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_03.h
- tests/someipsrv_format_03/someipsrv_format_03.scxml



### §5.1.5.1.4. 5.1.5.1.4


**Intent**: TC8 §5.1.5.1.4 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_04.h
- tests/someipsrv_format_04/someipsrv_format_04.scxml



### §5.1.5.1.5. 5.1.5.1.5


**Intent**: TC8 §5.1.5.1.5 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_05.h
- tests/someipsrv_format_05/someipsrv_format_05.scxml



### §5.1.5.1.6. 5.1.5.1.6


**Intent**: TC8 §5.1.5.1.6 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_06.h
- tests/someipsrv_format_06/someipsrv_format_06.scxml



### §5.1.5.1.7. 5.1.5.1.7


**Intent**: TC8 §5.1.5.1.7 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_07.h
- tests/someipsrv_format_07/someipsrv_format_07.scxml



### §5.1.5.1.8. 5.1.5.1.8


**Intent**: TC8 §5.1.5.1.8 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_08.h
- tests/someipsrv_format_08/someipsrv_format_08.scxml



### §5.1.5.1.9. 5.1.5.1.9


**Intent**: TC8 §5.1.5.1.9 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_format_09.h
- tests/someipsrv_format_09/someipsrv_format_09.scxml



### §5.1.5.2. 5.1.5.2


**Intent**: TC8 §5.1.5.2 — SOME/IP Server — Options. 15 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- tests/someipsrv_options_01/someipsrv_options_01.scxml
- tests/someipsrv_options_02/someipsrv_options_02.scxml
- tests/someipsrv_options_03/someipsrv_options_03.scxml
- tests/someipsrv_options_04/someipsrv_options_04.scxml
- tests/someipsrv_options_05/someipsrv_options_05.scxml
- tests/someipsrv_options_06/someipsrv_options_06.scxml
- tests/someipsrv_options_07/someipsrv_options_07.scxml
- tests/someipsrv_options_08/someipsrv_options_08.scxml
- tests/someipsrv_options_09/someipsrv_options_09.scxml
- tests/someipsrv_options_10/someipsrv_options_10.scxml
- tests/someipsrv_options_11/someipsrv_options_11.scxml
- tests/someipsrv_options_12/someipsrv_options_12.scxml
- tests/someipsrv_options_13/someipsrv_options_13.scxml
- tests/someipsrv_options_14/someipsrv_options_14.scxml
- tests/someipsrv_options_15/someipsrv_options_15.scxml



### §5.1.5.3. 5.1.5.3


**Intent**: TC8 §5.1.5.3 — SOME/IP-SD — Message. 17 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/env/smoke-test.sh
- dut/ets/ets.fdepl
- src/sce_integration/someip_captured.h
- tests/_templates/someipsrv_sd_field_check.sce-template.xml



### §5.1.5.3.1. 5.1.5.3.1


**Intent**: TC8 §5.1.5.3.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_01.h
- tests/someipsrv_sd_message_01/someipsrv_sd_message_01.scxml



### §5.1.5.3.11. 5.1.5.3.11


**Intent**: TC8 §5.1.5.3.11 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_11.h
- tests/someipsrv_sd_message_11/someipsrv_sd_message_11.scxml



### §5.1.5.3.13. 5.1.5.3.13


**Intent**: TC8 §5.1.5.3.13 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_13.h
- tests/someipsrv_sd_message_13/someipsrv_sd_message_13.scxml



### §5.1.5.3.14. 5.1.5.3.14


**Intent**: TC8 §5.1.5.3.14 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_14.h
- tests/someipsrv_sd_message_14/someipsrv_sd_message_14.scxml



### §5.1.5.3.15. 5.1.5.3.15


**Intent**: TC8 §5.1.5.3.15 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_15.h
- tests/someipsrv_sd_message_15/someipsrv_sd_message_15.scxml



### §5.1.5.3.16. 5.1.5.3.16


**Intent**: TC8 §5.1.5.3.16 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_16.h
- tests/someipsrv_sd_message_16/someipsrv_sd_message_16.scxml



### §5.1.5.3.17. 5.1.5.3.17


**Intent**: TC8 §5.1.5.3.17 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_17.h
- tests/someipsrv_sd_message_17/someipsrv_sd_message_17.scxml



### §5.1.5.3.18. 5.1.5.3.18


**Intent**: TC8 §5.1.5.3.18 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_18.h
- tests/someipsrv_sd_message_18/someipsrv_sd_message_18.scxml



### §5.1.5.3.19. 5.1.5.3.19


**Intent**: TC8 §5.1.5.3.19 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_19.h
- tests/someipsrv_sd_message_19/someipsrv_sd_message_19.scxml



### §5.1.5.3.2. 5.1.5.3.2


**Intent**: TC8 §5.1.5.3.2 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_02.h
- src/sce_integration/someip_captured.h
- tests/someipsrv_sd_message_02/someipsrv_sd_message_02.scxml



### §5.1.5.3.3. 5.1.5.3.3


**Intent**: TC8 §5.1.5.3.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_03.h
- tests/someipsrv_sd_message_03/someipsrv_sd_message_03.scxml



### §5.1.5.3.4. 5.1.5.3.4


**Intent**: TC8 §5.1.5.3.4 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_04.h
- tests/someipsrv_sd_message_04/someipsrv_sd_message_04.scxml



### §5.1.5.3.5. 5.1.5.3.5


**Intent**: TC8 §5.1.5.3.5 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_05.h
- tests/someipsrv_sd_message_05/someipsrv_sd_message_05.scxml



### §5.1.5.3.6. 5.1.5.3.6


**Intent**: TC8 §5.1.5.3.6 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_06.h
- tests/someipsrv_sd_message_06/someipsrv_sd_message_06.scxml



### §5.1.5.3.7. 5.1.5.3.7


**Intent**: TC8 §5.1.5.3.7 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_07.h
- tests/someipsrv_sd_message_07/someipsrv_sd_message_07.scxml



### §5.1.5.3.8. 5.1.5.3.8


**Intent**: TC8 §5.1.5.3.8 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_08.h
- tests/someipsrv_sd_message_08/someipsrv_sd_message_08.scxml



### §5.1.5.3.9. 5.1.5.3.9


**Intent**: TC8 §5.1.5.3.9 — auto-seeded TC8-internal sub-section (4 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_message_09.h
- src/sce_integration/someip_captured.h
- tests/someipsrv_sd_message_09/someipsrv_sd_message_09.scxml



### §5.1.5.4. 5.1.5.4


**Intent**: TC8 §5.1.5.4 — SOME/IP-SD — Behavior. 4 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/env/smoke-test.sh
- include/tc8/protocol_frames/someip_frame.h
- src/dissect/transport.h
- src/sce_integration/cases/_someipsrv_traits_base.h
- src/sce_integration/someip_captured.h
- src/sce_integration/someip_expectations.h
- src/sce_integration/someip_expected.h
- src/stimulus/someip_sd_builder.h



### §5.1.5.4.1. 5.1.5.4.1


**Intent**: TC8 §5.1.5.4.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_behavior_01.h
- tests/someipsrv_sd_behavior_01/someipsrv_sd_behavior_01.scxml



### §5.1.5.4.2. 5.1.5.4.2


**Intent**: TC8 §5.1.5.4.2 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_behavior_02.h
- tests/someipsrv_sd_behavior_02/someipsrv_sd_behavior_02.scxml



### §5.1.5.4.3. 5.1.5.4.3


**Intent**: TC8 §5.1.5.4.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_behavior_03.h
- tests/someipsrv_sd_behavior_03/someipsrv_sd_behavior_03.scxml



### §5.1.5.4.4. 5.1.5.4.4


**Intent**: TC8 §5.1.5.4.4 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_sd_behavior_04.h
- tests/someipsrv_sd_behavior_04/someipsrv_sd_behavior_04.scxml



### §5.1.5.5. 5.1.5.5


**Intent**: TC8 §5.1.5.5 — SOME/IP Server — Basic. 3 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/env/smoke-test.sh
- dut/ets/ets.fdepl
- src/sce_integration/cases/someip_ets_027.h
- src/sce_integration/cases/someip_ets_086.h
- src/sce_integration/cases/someip_ets_147.h
- src/sce_integration/cases/someip_ets_148.h
- src/sce_integration/cases/someip_ets_149.h
- src/sce_integration/cases/someip_ets_150.h
- src/sce_integration/cases/someip_ets_151.h
- src/sce_integration/someip_expectations.h
- src/sce_integration/someip_expected.h
- tests/_templates/someipsrv_sd_field_check.sce-template.xml
- tests/someip_ets_027/someip_ets_027.scxml



### §5.1.5.5.1. 5.1.5.5.1


**Intent**: TC8 §5.1.5.5.1 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_basic_01.h
- tests/someipsrv_basic_01/someipsrv_basic_01.scxml



### §5.1.5.5.2. 5.1.5.5.2


**Intent**: TC8 §5.1.5.5.2 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_basic_02.h
- tests/someipsrv_basic_02/someipsrv_basic_02.scxml



### §5.1.5.5.3. 5.1.5.5.3


**Intent**: TC8 §5.1.5.5.3 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_basic_03.h
- tests/someipsrv_basic_03/someipsrv_basic_03.scxml



### §5.1.5.6. 5.1.5.6


**Intent**: TC8 §5.1.5.6 — SOME/IP Server — On-Wire. 10 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- src/sce_integration/someip_captured.h
- tests/_templates/someipsrv_rpc_field_check.sce-template.xml



### §5.1.5.6.1. 5.1.5.6.1


**Intent**: TC8 §5.1.5.6.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_01.h
- tests/someipsrv_onwire_01/someipsrv_onwire_01.scxml



### §5.1.5.6.10. 5.1.5.6.10


**Intent**: TC8 §5.1.5.6.10 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_10.h
- tests/someipsrv_onwire_10/someipsrv_onwire_10.scxml



### §5.1.5.6.11. 5.1.5.6.11


**Intent**: TC8 §5.1.5.6.11 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_11.h
- tests/someipsrv_onwire_11/someipsrv_onwire_11.scxml



### §5.1.5.6.12. 5.1.5.6.12


**Intent**: TC8 §5.1.5.6.12 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_12.h
- tests/someipsrv_onwire_12/someipsrv_onwire_12.scxml



### §5.1.5.6.2. 5.1.5.6.2


**Intent**: TC8 §5.1.5.6.2 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_02.h
- tests/someipsrv_onwire_02/someipsrv_onwire_02.scxml



### §5.1.5.6.3. 5.1.5.6.3


**Intent**: TC8 §5.1.5.6.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_03.h
- tests/someipsrv_onwire_03/someipsrv_onwire_03.scxml



### §5.1.5.6.4. 5.1.5.6.4


**Intent**: TC8 §5.1.5.6.4 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_04.h
- tests/someipsrv_onwire_04/someipsrv_onwire_04.scxml



### §5.1.5.6.5. 5.1.5.6.5


**Intent**: TC8 §5.1.5.6.5 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_05.h
- tests/someipsrv_onwire_05/someipsrv_onwire_05.scxml



### §5.1.5.6.6. 5.1.5.6.6


**Intent**: TC8 §5.1.5.6.6 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_06.h
- tests/someipsrv_onwire_06/someipsrv_onwire_06.scxml



### §5.1.5.6.7. 5.1.5.6.7


**Intent**: TC8 §5.1.5.6.7 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_onwire_07.h
- tests/someipsrv_onwire_07/someipsrv_onwire_07.scxml



### §5.1.5.7. 5.1.5.7


**Intent**: TC8 §5.1.5.7 — SOME/IP Server — RPC / ETS. 154 active cases. SSOT: doc/spec/case_inventory.json.









**Implementations**:
- dut/dut_service/dut_main.cpp
- dut/dut_service/ets_impl.h
- dut/ets/ets.fdepl
- dut/ets/ets.fidl
- dut/ets/ets2.fidl
- src/sce_integration/someip_captured.h
- src/stimulus/someip_rpc_builder.h
- tests/_templates/someipsrv_rpc_field_check.sce-template.xml



### §5.1.5.7.1. 5.1.5.7.1


**Intent**: TC8 §5.1.5.7.1 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_01.h
- tests/someipsrv_rpc_01/someipsrv_rpc_01.scxml



### §5.1.5.7.10. 5.1.5.7.10


**Intent**: TC8 §5.1.5.7.10 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_10.h
- tests/someipsrv_rpc_10/someipsrv_rpc_10.scxml



### §5.1.5.7.11. 5.1.5.7.11


**Intent**: TC8 §5.1.5.7.11 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_11.h
- tests/someipsrv_rpc_11/someipsrv_rpc_11.scxml



### §5.1.5.7.13. 5.1.5.7.13


**Intent**: TC8 §5.1.5.7.13 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_13.h
- tests/someipsrv_rpc_13/someipsrv_rpc_13.scxml



### §5.1.5.7.14. 5.1.5.7.14


**Intent**: TC8 §5.1.5.7.14 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_14.h
- tests/someipsrv_rpc_14/someipsrv_rpc_14.scxml



### §5.1.5.7.17. 5.1.5.7.17


**Intent**: TC8 §5.1.5.7.17 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_17.h
- tests/someipsrv_rpc_17/someipsrv_rpc_17.scxml



### §5.1.5.7.18. 5.1.5.7.18


**Intent**: TC8 §5.1.5.7.18 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_18.h
- tests/someipsrv_rpc_18/someipsrv_rpc_18.scxml



### §5.1.5.7.19. 5.1.5.7.19


**Intent**: TC8 §5.1.5.7.19 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_19.h
- tests/someipsrv_rpc_19/someipsrv_rpc_19.scxml



### §5.1.5.7.2. 5.1.5.7.2


**Intent**: TC8 §5.1.5.7.2 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_02.h
- tests/someipsrv_rpc_02/someipsrv_rpc_02.scxml



### §5.1.5.7.20. 5.1.5.7.20


**Intent**: TC8 §5.1.5.7.20 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_20.h
- tests/someipsrv_rpc_20/someipsrv_rpc_20.scxml



### §5.1.5.7.3. 5.1.5.7.3


**Intent**: TC8 §5.1.5.7.3 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_03.h
- tests/someipsrv_rpc_03/someipsrv_rpc_03.scxml



### §5.1.5.7.4. 5.1.5.7.4


**Intent**: TC8 §5.1.5.7.4 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_04.h
- tests/someipsrv_rpc_04/someipsrv_rpc_04.scxml



### §5.1.5.7.5. 5.1.5.7.5


**Intent**: TC8 §5.1.5.7.5 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_05.h
- tests/someipsrv_rpc_05/someipsrv_rpc_05.scxml



### §5.1.5.7.6. 5.1.5.7.6


**Intent**: TC8 §5.1.5.7.6 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_06.h
- tests/someipsrv_rpc_06/someipsrv_rpc_06.scxml



### §5.1.5.7.7. 5.1.5.7.7


**Intent**: TC8 §5.1.5.7.7 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_07.h
- tests/someipsrv_rpc_07/someipsrv_rpc_07.scxml



### §5.1.5.7.8. 5.1.5.7.8


**Intent**: TC8 §5.1.5.7.8 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_08.h
- tests/someipsrv_rpc_08/someipsrv_rpc_08.scxml



### §5.1.5.7.9. 5.1.5.7.9


**Intent**: TC8 §5.1.5.7.9 — auto-seeded TC8-internal sub-section (2 code citations at baseline).









**Implementations**:
- src/sce_integration/cases/someipsrv_rpc_09.h
- tests/someipsrv_rpc_09/someipsrv_rpc_09.scxml



### §5.1.6. 5.1.6


**Intent**: TC8 §5.1.6 — auto-seeded TC8-internal sub-section (584 code citations at baseline).









**Implementations**:
- dut/dut_service/client_mode.h
- dut/dut_service/client_mode_proxy.h
- dut/dut_service/dut_main.cpp
- dut/dut_service/ets_impl.cpp
- dut/dut_service/ets_impl.h
- dut/env/smoke-test.sh
- dut/ets/CMakeLists.txt
- dut/ets/ets.fdepl
- dut/ets/ets.fidl
- dut/ets/ets3.fdepl
- dut/ets/ets3.fidl
- src/sce_integration/cases/someip_ets_001.h
- src/sce_integration/cases/someip_ets_002.h
- src/sce_integration/cases/someip_ets_003.h
- src/sce_integration/cases/someip_ets_004.h
- src/sce_integration/cases/someip_ets_005.h
- src/sce_integration/cases/someip_ets_007.h
- src/sce_integration/cases/someip_ets_008.h
- src/sce_integration/cases/someip_ets_009.h
- src/sce_integration/cases/someip_ets_019.h
- src/sce_integration/cases/someip_ets_021.h
- src/sce_integration/cases/someip_ets_022.h
- src/sce_integration/cases/someip_ets_027.h
- src/sce_integration/cases/someip_ets_028.h
- src/sce_integration/cases/someip_ets_029.h
- src/sce_integration/cases/someip_ets_030.h
- src/sce_integration/cases/someip_ets_031.h
- src/sce_integration/cases/someip_ets_032.h
- src/sce_integration/cases/someip_ets_033.h
- src/sce_integration/cases/someip_ets_034.h
- src/sce_integration/cases/someip_ets_035.h
- src/sce_integration/cases/someip_ets_037.h
- src/sce_integration/cases/someip_ets_038.h
- src/sce_integration/cases/someip_ets_039.h
- src/sce_integration/cases/someip_ets_040.h
- src/sce_integration/cases/someip_ets_041.h
- src/sce_integration/cases/someip_ets_042.h
- src/sce_integration/cases/someip_ets_043.h
- src/sce_integration/cases/someip_ets_044.h
- src/sce_integration/cases/someip_ets_045.h
- src/sce_integration/cases/someip_ets_046.h
- src/sce_integration/cases/someip_ets_047.h
- src/sce_integration/cases/someip_ets_048.h
- src/sce_integration/cases/someip_ets_049.h
- src/sce_integration/cases/someip_ets_050.h
- src/sce_integration/cases/someip_ets_051.h
- src/sce_integration/cases/someip_ets_052.h
- src/sce_integration/cases/someip_ets_053.h
- src/sce_integration/cases/someip_ets_054.h
- src/sce_integration/cases/someip_ets_055.h
- src/sce_integration/cases/someip_ets_058.h
- src/sce_integration/cases/someip_ets_059.h
- src/sce_integration/cases/someip_ets_060.h
- src/sce_integration/cases/someip_ets_061.h
- src/sce_integration/cases/someip_ets_063.h
- src/sce_integration/cases/someip_ets_064.h
- src/sce_integration/cases/someip_ets_065.h
- src/sce_integration/cases/someip_ets_066.h
- src/sce_integration/cases/someip_ets_067.h
- src/sce_integration/cases/someip_ets_068.h
- src/sce_integration/cases/someip_ets_069.h
- src/sce_integration/cases/someip_ets_070.h
- src/sce_integration/cases/someip_ets_071.h
- src/sce_integration/cases/someip_ets_072.h
- src/sce_integration/cases/someip_ets_073.h
- src/sce_integration/cases/someip_ets_074.h
- src/sce_integration/cases/someip_ets_075.h
- src/sce_integration/cases/someip_ets_076.h
- src/sce_integration/cases/someip_ets_077.h
- src/sce_integration/cases/someip_ets_078.h
- src/sce_integration/cases/someip_ets_081.h
- src/sce_integration/cases/someip_ets_082.h
- src/sce_integration/cases/someip_ets_084.h
- src/sce_integration/cases/someip_ets_086.h
- src/sce_integration/cases/someip_ets_087.h
- src/sce_integration/cases/someip_ets_088.h
- src/sce_integration/cases/someip_ets_089.h
- src/sce_integration/cases/someip_ets_091.h
- src/sce_integration/cases/someip_ets_092.h
- src/sce_integration/cases/someip_ets_093.h
- src/sce_integration/cases/someip_ets_094.h
- src/sce_integration/cases/someip_ets_095.h
- src/sce_integration/cases/someip_ets_096.h
- src/sce_integration/cases/someip_ets_097.h
- src/sce_integration/cases/someip_ets_098.h
- src/sce_integration/cases/someip_ets_099.h
- src/sce_integration/cases/someip_ets_100.h
- src/sce_integration/cases/someip_ets_101.h
- src/sce_integration/cases/someip_ets_103.h
- src/sce_integration/cases/someip_ets_104.h
- src/sce_integration/cases/someip_ets_105.h
- src/sce_integration/cases/someip_ets_106.h
- src/sce_integration/cases/someip_ets_107.h
- src/sce_integration/cases/someip_ets_108.h
- src/sce_integration/cases/someip_ets_109.h
- src/sce_integration/cases/someip_ets_110.h
- src/sce_integration/cases/someip_ets_111.h
- src/sce_integration/cases/someip_ets_112.h
- src/sce_integration/cases/someip_ets_113.h
- src/sce_integration/cases/someip_ets_114.h
- src/sce_integration/cases/someip_ets_115.h
- src/sce_integration/cases/someip_ets_116.h
- src/sce_integration/cases/someip_ets_117.h
- src/sce_integration/cases/someip_ets_118.h
- src/sce_integration/cases/someip_ets_119.h
- src/sce_integration/cases/someip_ets_120.h
- src/sce_integration/cases/someip_ets_121.h
- src/sce_integration/cases/someip_ets_122.h
- src/sce_integration/cases/someip_ets_123.h
- src/sce_integration/cases/someip_ets_124.h
- src/sce_integration/cases/someip_ets_125.h
- src/sce_integration/cases/someip_ets_127.h
- src/sce_integration/cases/someip_ets_128.h
- src/sce_integration/cases/someip_ets_130.h
- src/sce_integration/cases/someip_ets_134.h
- src/sce_integration/cases/someip_ets_135.h
- src/sce_integration/cases/someip_ets_136.h
- src/sce_integration/cases/someip_ets_137.h
- src/sce_integration/cases/someip_ets_138.h
- src/sce_integration/cases/someip_ets_139.h
- src/sce_integration/cases/someip_ets_140.h
- src/sce_integration/cases/someip_ets_141.h
- src/sce_integration/cases/someip_ets_142.h
- src/sce_integration/cases/someip_ets_143.h
- src/sce_integration/cases/someip_ets_144.h
- src/sce_integration/cases/someip_ets_146.h
- src/sce_integration/cases/someip_ets_147.h
- src/sce_integration/cases/someip_ets_148.h
- src/sce_integration/cases/someip_ets_149.h
- src/sce_integration/cases/someip_ets_150.h
- src/sce_integration/cases/someip_ets_151.h
- src/sce_integration/cases/someip_ets_152.h
- src/sce_integration/cases/someip_ets_153.h
- src/sce_integration/cases/someip_ets_154.h
- src/sce_integration/cases/someip_ets_155.h
- src/sce_integration/cases/someip_ets_162.h
- src/sce_integration/cases/someip_ets_163.h
- src/sce_integration/cases/someip_ets_164.h
- src/sce_integration/cases/someip_ets_166.h
- src/sce_integration/cases/someip_ets_167.h
- src/sce_integration/cases/someip_ets_168.h
- src/sce_integration/cases/someip_ets_171.h
- src/sce_integration/cases/someip_ets_173.h
- src/sce_integration/cases/someip_ets_174.h
- src/sce_integration/cases/someip_ets_175.h
- src/sce_integration/cases/someip_ets_176.h
- src/sce_integration/cases/someip_ets_177.h
- src/sce_integration/cases/someip_ets_178.h
- src/sce_integration/someip_captured.h
- src/stimulus/someip_rpc_builder.cpp
- src/stimulus/someip_rpc_builder.h
- src/stimulus/someip_sd_builder.cpp
- src/stimulus/someip_sd_builder.h
- tests/someip_ets_001/someip_ets_001.scxml
- tests/someip_ets_002/someip_ets_002.scxml
- tests/someip_ets_003/someip_ets_003.scxml
- tests/someip_ets_004/someip_ets_004.scxml
- tests/someip_ets_005/someip_ets_005.scxml
- tests/someip_ets_007/someip_ets_007.scxml
- tests/someip_ets_008/someip_ets_008.scxml
- tests/someip_ets_009/someip_ets_009.scxml
- tests/someip_ets_019/someip_ets_019.scxml
- tests/someip_ets_021/someip_ets_021.scxml
- tests/someip_ets_022/someip_ets_022.scxml
- tests/someip_ets_027/someip_ets_027.scxml
- tests/someip_ets_028/someip_ets_028.scxml
- tests/someip_ets_029/someip_ets_029.scxml
- tests/someip_ets_030/someip_ets_030.scxml
- tests/someip_ets_031/someip_ets_031.scxml
- tests/someip_ets_032/someip_ets_032.scxml
- tests/someip_ets_033/someip_ets_033.scxml
- tests/someip_ets_034/someip_ets_034.scxml
- tests/someip_ets_035/someip_ets_035.scxml
- tests/someip_ets_037/someip_ets_037.scxml
- tests/someip_ets_038/someip_ets_038.scxml
- tests/someip_ets_039/someip_ets_039.scxml
- tests/someip_ets_040/someip_ets_040.scxml
- tests/someip_ets_041/someip_ets_041.scxml
- tests/someip_ets_042/someip_ets_042.scxml
- tests/someip_ets_043/someip_ets_043.scxml
- tests/someip_ets_044/someip_ets_044.scxml
- tests/someip_ets_045/someip_ets_045.scxml
- tests/someip_ets_046/someip_ets_046.scxml
- tests/someip_ets_047/someip_ets_047.scxml
- tests/someip_ets_048/someip_ets_048.scxml
- tests/someip_ets_049/someip_ets_049.scxml
- tests/someip_ets_050/someip_ets_050.scxml
- tests/someip_ets_051/someip_ets_051.scxml
- tests/someip_ets_052/someip_ets_052.scxml
- tests/someip_ets_053/someip_ets_053.scxml
- tests/someip_ets_054/someip_ets_054.scxml
- tests/someip_ets_055/someip_ets_055.scxml
- tests/someip_ets_058/someip_ets_058.scxml
- tests/someip_ets_059/someip_ets_059.scxml
- tests/someip_ets_060/someip_ets_060.scxml
- tests/someip_ets_061/someip_ets_061.scxml
- tests/someip_ets_063/someip_ets_063.scxml
- tests/someip_ets_064/someip_ets_064.scxml
- tests/someip_ets_065/someip_ets_065.scxml
- tests/someip_ets_066/someip_ets_066.scxml
- tests/someip_ets_067/someip_ets_067.scxml
- tests/someip_ets_068/someip_ets_068.scxml
- tests/someip_ets_069/someip_ets_069.scxml
- tests/someip_ets_070/someip_ets_070.scxml
- tests/someip_ets_071/someip_ets_071.scxml
- tests/someip_ets_072/someip_ets_072.scxml
- tests/someip_ets_073/someip_ets_073.scxml
- tests/someip_ets_074/someip_ets_074.scxml
- tests/someip_ets_075/someip_ets_075.scxml
- tests/someip_ets_076/someip_ets_076.scxml
- tests/someip_ets_077/someip_ets_077.scxml
- tests/someip_ets_078/someip_ets_078.scxml
- tests/someip_ets_081/someip_ets_081.scxml
- tests/someip_ets_082/someip_ets_082.scxml
- tests/someip_ets_084/someip_ets_084.scxml
- tests/someip_ets_086/someip_ets_086.scxml
- tests/someip_ets_087/someip_ets_087.scxml
- tests/someip_ets_088/someip_ets_088.scxml
- tests/someip_ets_089/someip_ets_089.scxml
- tests/someip_ets_091/someip_ets_091.scxml
- tests/someip_ets_092/someip_ets_092.scxml
- tests/someip_ets_093/someip_ets_093.scxml
- tests/someip_ets_094/someip_ets_094.scxml
- tests/someip_ets_095/someip_ets_095.scxml
- tests/someip_ets_096/someip_ets_096.scxml
- tests/someip_ets_097/someip_ets_097.scxml
- tests/someip_ets_098/someip_ets_098.scxml
- tests/someip_ets_099/someip_ets_099.scxml
- tests/someip_ets_100/someip_ets_100.scxml
- tests/someip_ets_101/someip_ets_101.scxml
- tests/someip_ets_103/someip_ets_103.scxml
- tests/someip_ets_104/someip_ets_104.scxml
- tests/someip_ets_105/someip_ets_105.scxml
- tests/someip_ets_106/someip_ets_106.scxml
- tests/someip_ets_107/someip_ets_107.scxml
- tests/someip_ets_108/someip_ets_108.scxml
- tests/someip_ets_109/someip_ets_109.scxml
- tests/someip_ets_110/someip_ets_110.scxml
- tests/someip_ets_111/someip_ets_111.scxml
- tests/someip_ets_112/someip_ets_112.scxml
- tests/someip_ets_113/someip_ets_113.scxml
- tests/someip_ets_114/someip_ets_114.scxml
- tests/someip_ets_115/someip_ets_115.scxml
- tests/someip_ets_116/someip_ets_116.scxml
- tests/someip_ets_117/someip_ets_117.scxml
- tests/someip_ets_118/someip_ets_118.scxml
- tests/someip_ets_119/someip_ets_119.scxml
- tests/someip_ets_120/someip_ets_120.scxml
- tests/someip_ets_121/someip_ets_121.scxml
- tests/someip_ets_122/someip_ets_122.scxml
- tests/someip_ets_123/someip_ets_123.scxml
- tests/someip_ets_124/someip_ets_124.scxml
- tests/someip_ets_125/someip_ets_125.scxml
- tests/someip_ets_127/someip_ets_127.scxml
- tests/someip_ets_128/someip_ets_128.scxml
- tests/someip_ets_130/someip_ets_130.scxml
- tests/someip_ets_134/someip_ets_134.scxml
- tests/someip_ets_135/someip_ets_135.scxml
- tests/someip_ets_136/someip_ets_136.scxml
- tests/someip_ets_137/someip_ets_137.scxml
- tests/someip_ets_138/someip_ets_138.scxml
- tests/someip_ets_139/someip_ets_139.scxml
- tests/someip_ets_140/someip_ets_140.scxml
- tests/someip_ets_141/someip_ets_141.scxml
- tests/someip_ets_142/someip_ets_142.scxml
- tests/someip_ets_143/someip_ets_143.scxml
- tests/someip_ets_144/someip_ets_144.scxml
- tests/someip_ets_146/someip_ets_146.scxml
- tests/someip_ets_147/someip_ets_147.scxml
- tests/someip_ets_148/someip_ets_148.scxml
- tests/someip_ets_149/someip_ets_149.scxml
- tests/someip_ets_150/someip_ets_150.scxml
- tests/someip_ets_151/someip_ets_151.scxml
- tests/someip_ets_152/someip_ets_152.scxml
- tests/someip_ets_153/someip_ets_153.scxml
- tests/someip_ets_154/someip_ets_154.scxml
- tests/someip_ets_155/someip_ets_155.scxml
- tests/someip_ets_162/someip_ets_162.scxml
- tests/someip_ets_163/someip_ets_163.scxml
- tests/someip_ets_164/someip_ets_164.scxml
- tests/someip_ets_166/someip_ets_166.scxml
- tests/someip_ets_167/someip_ets_167.scxml
- tests/someip_ets_168/someip_ets_168.scxml
- tests/someip_ets_171/someip_ets_171.scxml
- tests/someip_ets_173/someip_ets_173.scxml
- tests/someip_ets_174/someip_ets_174.scxml
- tests/someip_ets_175/someip_ets_175.scxml
- tests/someip_ets_176/someip_ets_176.scxml
- tests/someip_ets_177/someip_ets_177.scxml
- tests/someip_ets_178/someip_ets_178.scxml



### §5.3. 5.3


**Intent**: TC8 §5.3 — auto-seeded TC8-internal sub-section (3 code citations at baseline).









**Implementations**:
- include/tc8/upper_tester_protocol.h
- src/sce_integration/cases/tcp_retransmission_to_03.h
- tests/tcp_retransmission_to_03/tcp_retransmission_to_03.scxml



## Changelog (atomic ledger)

### Round 1 — 9 TC8 cases tightened to expose Linux/vsomeip deviations honestly; CI grep filter expanded for known-fail excuses.

**Changes**:
- SOMEIP_ETS_117: strict Nack OR ignore (was Nack OR Ack OR ignore)
- ICMPV4_ERROR_02: strict pointer == 22 (was {20, 22})
- TCP_UNACCEPTABLE_04/_08/_10: phase 2 added via scheduleAfterStateEntry
- TCP_FLAGS_INVALID_15: FW2 + TW absence guards re-add is_pure_dut_ack
- ARP_33/_34: TC8 spec-literal target_hw=broadcast on gratuitous Responses
- .github/workflows/smoke-test.yml line 141 grep-vE pattern expanded



**Verification**:
- Negative smoke 321 cases audited: 0 false positives
- Spec coverage 543/543 active unchanged
- Linux-runnable green-bar 549/549 -> 540/549
- claudedocs/false_positive_audit_2026_05_07.md baseline



**Impact**: §4.2.4.2, §4.3.3.1, §4.8.6.3, §4.8.6.6, §5.1.5.7


**Carry forward**:
- SOMEIPSRV §5.1.5 deeper alignment audit deferred to Round 2
- Silent-FP cross-read (asymmetric-sister-cluster) deferred to Round 2



### Round 2 — SOMEIPSRV §5.1.5 deeper alignment + silent-FP cross-read; 6 cases tightened via Type-1 entry gate + Nack-TTL accept removal.

**Changes**:
- SOMEIPSRV_FORMAT_14/_15/_16/_17/_18: sd_entries[0].type == 0x01 gate prefix
- SOMEIPSRV_FORMAT_26: pass cond drops Nack-accept TTL=0 clause



**Verification**:
- 93/93 SOMEIPSRV active cases audited
- 0 new CI filter entries
- Spec coverage 543/543 unchanged
- Smoke regression --workers 4 on 93-case set: 93/93 pass
- Cumulative rounds 1-2: 15 tightened



**Impact**: §5.1.5.1


**Carry forward**:
- FORMAT_27 R4.1 vs R4.2+ Counter mirroring carve-out (docs only) -> Round 3
- SD_BEHAVIOR_03/_04 cyclic-Offer leak phase boundaries -> Round 3
- SD_MESSAGE_02 sequential-allocator hardcode -> Round 3
- FORMAT_01..06 SomeIpAnyBase -> SdOnlyBase swap -> Round 3



### Round 3 — Phase B closed 4 SOMEIPSRV Round 2 caveats (SdOnlyBase + phase retiming + dynamic instance + docs). Phase A sampled ETS/TCP — 0 silent FPs in 35.

**Changes**:
- SOMEIPSRV_FORMAT_01..06: SomeIpAnyBase -> SomeIpSdOnlyBase (6 traits)
- SD_BEHAVIOR_03: stimulus 4500->4040ms; Phase 1 5500->3940ms; Phase 2 4000->1500ms
- SD_BEHAVIOR_04: same retiming + CI grep filter expanded
- SD_MESSAGE_02: 3-phase verdict with extracted_instance_id_1/_2 slots (TR_SOMEIP_00351)
- FORMAT_27: SCXML comment expanded for R4.1 vs R4.2+ Counter carve-out



**Verification**:
- Phase B 8 cases tightened + 1 docs
- CI grep filter +1 (SOMEIPSRV_SD_BEHAVIOR_04)
- Cross-cluster regression 92/92 SOMEIPSRV pass (BEHAVIOR_04 excluded)
- Linux-runnable green-bar 540/549 -> 539/549
- Spec coverage 543/543 active unchanged
- Cumulative rounds 1-3: 23 tightened



**Impact**: §5.1.5.1, §5.1.5.3, §5.1.5.4


**Carry forward**:
- TCP §4.8 sub-areas (~85 cases) deferred to Round 4
- DHCPv4 §4.7 (52), IPv4 §4.4/§4.5 (59), UDP §4.6 (31), ICMPv4 §4.3 (13), ARP §4.2 -> Round 4



### Round 4 — Cross-read TCP §4.8 + ARP §4.2 + DHCPv4 §4.7 + ICMPv4 §4.3; 12 cases tightened. 12 multi-phase active-OPEN HALF-COVERAGE blocked by harness-model constraint.

**Changes**:
- TCP_UNACCEPTABLE_06: single-phase ack_num verification
- TCP_FLAGS_INVALID_07: fixed-ISN raw-inject ack_num verification
- ARP_07..15: 8 cases gated by sender_hw == DUT MAC
- ICMPV4_TYPE_08/_09: gated by src_ip == DUT IP



**Verification**:
- 12 tightened, 12 documented blocked, ~155 audited clean
- 4 commits landed (8ac7bcf, e082bde, d60b98d, 5fd8e8e)
- CI grep filter unchanged at 10 entries
- Spec coverage 543/543 active maintained
- Cumulative rounds 1-4: 35 tightened



**Impact**: §4.2.4.1, §4.3.3.2, §4.8.6.3, §4.8.6.6


**Carry forward**:
- 12 multi-phase active-OPEN HALF-COVERAGE (UNACCEPTABLE/FLAGS_INVALID) -> Round 5
- Per-phase captured slot infra needed (TcpCaptured extension)
- ETS §5.1.6 (137 cases) still untouched -> Round 6



### Round 5 — Closed 12 deferred TCP HALF-COVERAGE via per-phase captured slot infra + audited IPv4/UDP §4.4-§4.6 (3 actionable in FRAGMENTS/REASSEMBLY).

**Changes**:
- TcpCaptured: +expected_ack_num_phase3/_phase4/_phase5 slots (infra)
- UNACCEPTABLE_09/_11/_12/_13/_14: 2-phase HALF-COVERAGE close (per-phase ack_num)
- FLAGS_INVALID_14: TIME-WAIT 2-phase ack_num verification
- FLAGS_INVALID_08..13: 5-phase HALF-COVERAGE close
- IPV4_FRAGMENTS_01: gated by src_ip == dut_iface_ip
- IPV4_REASSEMBLY_04/_10: same src_ip gate



**Verification**:
- 15 tightened (12 TCP + 3 IPv4)
- 5 commits (176c695, e76402f, f5375c9, e5e240a, db1772b)
- CI grep filter unchanged at 10 entries
- Spec coverage 543/543 active maintained
- Cumulative rounds 1-5: 50 tightened



**Impact**: §4.4.4.6, §4.4.4.7, §4.8.6.3, §4.8.6.6


**Carry forward**:
- SOMEIP_ETS §5.1.6 (137 cases) untouched -> Round 6



### Round 6 — Audited 137 SOMEIP_ETS §5.1.6 — 10 tightened (6 HALF-COVERAGE payload echo + 2 transport src_port + 2 UDP bundle per-phase payload).

**Changes**:
- ETS_046/_047/_053: pin bytes [0..15] full echo (was partial)
- ETS_041/_050: bytes [0..15] phase 2 echo (UTF DYNAMIC)
- ETS_167: phase 3+4 payload_len == 8 + array byte verification
- ETS_068: TCP src_port gate per phase (echoUINT8RELIABLE)
- ETS_103: UDP src_port gate (pcap-empirical correction from tcp_port)
- ETS_061: 2-msg UDP bundle per-phase payload pin
- ETS_069: 3-msg UDP bundle per-phase payload pin



**Verification**:
- 10 cases tightened, ~127 audited clean
- 0 infra changes
- CI grep filter unchanged at 10 entries
- Spec coverage 543/543 active maintained
- 5 commits
- Cumulative rounds 1-6: 60 tightened



**Impact**: §5.1.5.7


**Carry forward**:
- kMaxPayloadBytes 16-byte cap cross-cutting infra -> Round 7.2
- TC8 NEG_ROWS re-audit (321 rows) -> Round 7.1
- inventory_overrides.json SSOT migration -> Round 7.3
- smoke-test.sh leftover-pkill PID-file fix -> Round 7.4



### Round 7.1 — Audited 321-row TC8 NEG_ROWS — 4 stale rows fixed (1 silent-FP miss + 3 reason-text drift); 1.2 percent hit rate.

**Changes**:
- SOMEIPSRV_SD_MESSAGE_02: flip axis swapped to service_id=0x0000; reason updated
- ARP_33: NEG reason updated to udp_eth_dst_is_mac1_not_mac2
- ARP_34: NEG reason updated to udp_eth_dst_is_mac1_not_mac2
- TCP_UNACCEPTABLE_08: NEG reason updated (_to_synack_ -> _phase1_synack_)



**Verification**:
- 4 tightened, 317 clean
- Single commit c6681fd
- CI grep filter unchanged at 10 entries
- Spec coverage 543/543 active maintained
- Cumulative rounds 1-7.1: 64 tightened



**Impact**: §4.2.4.2, §4.8.6.3, §5.1.5.3


**Carry forward**:
- kMaxPayloadBytes cap -> Round 7.2
- inventory_overrides.json SSOT migration -> Round 7.3
- smoke-test.sh PID-file fix -> Round 7.4



### Round 7.2 — Raised SomeIpCaptured kMaxPayloadBytes 16->144 + added payload_bytes_eq helper; migrated 7 ETS cases to full-payload echo verification.

**Changes**:
- kMaxPayloadBytes 16 -> 144 (132 B max + 12 B margin)
- SomeIpCaptured::payload_bytes_eq(initializer_list<uint8_t>) helper added
- ETS_008 (27 B), _034 (17 B): migrated to full-payload echo
- ETS_041, _050: 132 B full-payload echo (UTF DYNAMIC)
- ETS_046, _047, _053: 64 B full-payload echo (UTF FIXED)



**Verification**:
- 7 tightened
- 1 infra change (someip_captured.h cap + helper)
- CI grep filter 0 changes
- Spec coverage 543/543 active maintained
- Pcap-empirical verification on ETS_050 caught 133-vs-132 off-by-one
- Cumulative rounds 1-7.2: 71 tightened



**Impact**: §5.1.5.7


**Carry forward**:
- inventory_overrides.json SSOT migration -> Round 7.3
- smoke-test.sh PID-file fix -> Round 7.4



### Round 7.3 — Migrated 13-entry CI grep filter to inventory_overrides.json with new linux_known_fail axis (orthogonal to expected:false); --vs-spec honesty preserved.

**Changes**:
- inventory_overrides.json schema_version 1->2; +linux_known_fail field
- 13 entries populated with memory cross-refs
- SpecCase struct: +bool linux_known_fail + std::string linux_known_fail_ref
- TestCommand: +--exclude-linux-known-fail flag
- .github/workflows/smoke-test.yml: 60-line grep collapsed to 2 flag invocations



**Verification**:
- 0 cases tightened (infra-only)
- --list-cases --vs-spec: 543/543 honest coverage maintained
- --list-cases --exclude-linux-known-fail: 540 (553-13)
- 6-case --workers 4 smoke regression passes



**Impact**: §4.2.4.2, §4.3.3.1, §4.4.4.7, §4.8.6.3, §4.8.6.6, §4.8.6.11, §5.1.5.4, §5.1.5.7


**Carry forward**:
- smoke-test.sh PID-file fix -> Round 7.4



### Round 7.4 — PID-scoped smoke-test.sh scratch dirs + stale-scope GC; replaced broken pre-run pkill that didn't match symlink-cmdline workers.

**Changes**:
- smoke-test.sh: WORK_ROOT=/tmp/tc8-workers.$$ + VSOMEIP_BASE=/tmp/tc8-vsomeip.$$
- Startup GC scans sibling stale scopes via kill -0 owner check
- Legacy migration cleanup (hyphen-separator paths wiped)
- Symlink-cmdline pkill replaces real-path pkill (matches argv[0])
- +86 / -26 lines



**Verification**:
- bash -n syntax clean
- Single-worker smoke: ARP_03 passes
- 4-worker smoke: 4 cases all pass
- JUnit emission valid via --workers 4 --junit-xml
- Stale-GC: PID 999999 fake stale dirs reaped
- 0 cases tightened (infra)
- Spec coverage 543/543 active maintained



**Impact**: §4.2.4.1



### Round 8.1 — Audited UDP §4.6 (31) + IPv4 §4.5 autoconf (29) — 0 strict false-positives; 2 coverage gaps (UDP UI_07/_08 vacuous on single-iface DUT) deferred.

**Changes**:
- 60 cases audited (31 UDP + 29 §4.5 autoconf)
- 0 tightenings landed



**Verification**:
- 0 strict FPs
- 2 coverage-axis findings (UDP UI_07/_08 single-iface)
- Cumulative rounds 1-8.1: 71 tightened (no change)
- Spec coverage 543/543 active maintained



**Impact**: §4.5.6.2, §4.5.6.3, §4.5.6.4, §4.6.5.4, §4.6.5.5


**Carry forward**:
- Phase 3 sysctl toggle inventory -> Round 8.2
- Phase 4 UT fault-injection enum exhaustiveness -> Round 8.2
- Phase 5 cross-case state leakage -> Round 8.3
- UDP UI_07/_08 multi-iface -> RESOLVED 2026-05-10 commits 3f04340 + 4932266



### Round 8.2 — Audited 9 smoke-test.sh sysctl toggles + 1 fault-injection enum (LinklocalAutoconfFlavor) — 0 strict FPs, 0 build-flag gaps. ARP_39/40 + ARP_48/49 forward-defense mirror APPLIED.

**Changes**:
- smoke-test.sh:2607-2611 + :3142-3146: ARP_39/40 arp_ignore=8 mirror
- smoke-test.sh:2620-2627 + :3149-3158: ARP_48/49 neigh GC sysctls mirror
- ARP_38 precedent extended to ARP_39/40 + ARP_48/49 — uniform symmetric convention
- 4 NEG cases (ARP_39/40/48/49) verified PASS with mirrored toggles



**Verification**:
- 0 strict FPs in 9 toggles + 2 enum switches
- -Wswitch -Werror already wired (CMakeLists.txt:13-32)
- 0 code changes for FP closure (mirrors APPLIED separately)
- Cumulative rounds 1-8.2: 71 tightened (no change)
- Spec coverage 543/543 active maintained



**Impact**: §4.2.4.2


**Carry forward**:
- Phase 5 cross-case state leakage -> Round 8.3



### Round 8.3 — Audited 5 cross-case state inventories — 0 strict FPs; 2 dormant risks RETIRED via per-case unique offsets (commit 32384bf).

**Changes**:
- tcp_pilot_common.h:150-463: monotonic offset map +0..+224 with reservations
- 19 cases migrated to per-case unique offsets (+200..+224 block)
- Bare-port active-OPEN collision RETIRED (BASICS_11 EADDRNOTAVAIL pattern)
- CONN_ESTAB_03 cooldown dormant risk RETIRED
- helper default-arg removal: compile-time guard against future bare-port callers



**Verification**:
- 5 inventories audited (port quads / echo_id / ARP cache / vsomeip session_id / UDP bind)
- 0 strict FPs across all 5
- 2 dormant risks retired
- Cumulative rounds 1-8: 71 tightened (no change)
- Spec coverage 543/543 active maintained
- Round 8 closed (all 3 phases done)



**Impact**: §4.8.6.1, §4.8.6.3, §4.8.6.15



