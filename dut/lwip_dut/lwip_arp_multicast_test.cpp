// In-process runtime test for the lwIP backend's multicast (IGMP) and ARP (etharp)
// ops — the capabilities R2 enabled by building tc8-lwip-utm against an IGMP-on
// core (utm/lwipopts.h) — and for the answers where lwIP differs from the backend
// contract on its own: removing a learned ARP entry, the whole length of a datagram
// read into a short buffer, Don't Fragment, and a TCP socket whose pcb is gone.
// These paths are otherwise only build-verified.
//
// Multicast join/leave and etharp need a real ethernet interface, which normally
// means a tap device (root / netns). To stay in-process with no privileges, this
// test registers a STUB ethernet netif: NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP with a
// link-output that drops frames (there is no wire — the IGMP report and any ARP
// frame are simply discarded). That is enough to exercise the backend wrappers for
// real: igmp_joingroup runs, the static ARP entry lands in arp_table and is found,
// and the error/idempotent return mapping is observed. Built only into the UTM
// (IGMP-on) core; the conformance binaries take the #else (false) branches.
//
// C++ / tc8 headers FIRST, lwIP headers LAST + only the lwip_* socket forms — the
// same LWIP_COMPAT_SOCKETS macro-collision discipline as lwip_reactor_test.cpp.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "lwip_socket_backend.h"
#include "lwip_tcp_info_reader.h"
#include "tc8/testability_protocol.h"

#include "lwip/etharp.h"
#include "lwip/igmp.h"
#include "lwip/pbuf.h"
#include "lwip/prot/etharp.h"
#include "lwip/sockets.h"
#include "netif/ethernet.h"
#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/prot/ethernet.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

namespace {

int g_failures = 0;
void check(bool ok, const char *what) {
    std::fprintf(stderr, ok ? "ok: %s\n" : "FAIL: %s\n", what);
    if (!ok) {
        ++g_failures;
    }
}

// The capability ops answer an OpStatus, so assert the exact one: "it failed" was
// the defect, and a test that only checks for failure would carry it forward.
// Reports both names, so a wrong-but-failing status is legible.
void checkStatus(tc8::net::OpStatus got, tc8::net::OpStatus want, const char *what) {
    if (got == want) {
        std::fprintf(stderr, "ok: %s (%s)\n", what, tc8::net::toString(want));
        return;
    }
    std::fprintf(stderr, "FAIL: %s — want %s, got %s\n", what, tc8::net::toString(want),
                 tc8::net::toString(got));
    ++g_failures;
}

void initSemSignal(void *sem) { sys_sem_signal(static_cast<sys_sem_t *>(sem)); }

// Bring up the lwIP stack (tcpip_init also creates the 127/8 loopif). No tap.
void bringUpStack() {
    sys_sem_t init_sem;
    if (sys_sem_new(&init_sem, 0) != ERR_OK) {
        std::fprintf(stderr, "FATAL: sys_sem_new failed\n");
        std::exit(3);
    }
    tcpip_init(initSemSignal, &init_sem);
    sys_sem_wait(&init_sem);
    sys_sem_free(&init_sem);
}

err_t stubLinkOutput(struct netif *netif, struct pbuf *p) {
    (void)netif;
    (void)p;
    return ERR_OK;  // no wire: discard (IGMP reports, ARP requests)
}

err_t stubNetifInit(struct netif *netif) {
    netif->name[0] = 's';
    netif->name[1] = 't';  // "st" + the globally-unique num lwIP assigns (see main)
    netif->output = etharp_output;
    netif->linkoutput = stubLinkOutput;
    netif->mtu = 1500;
    netif->hwaddr_len = ETH_HWADDR_LEN;
    const std::uint8_t mac[ETH_HWADDR_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    std::memcpy(netif->hwaddr, mac, ETH_HWADDR_LEN);
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET |
                   NETIF_FLAG_IGMP;
    return ERR_OK;
}

struct netif g_stub;

// Add the stub ethernet netif (192.168.50.1/24) under the core lock and bring it
// up — netif_set_up starts IGMP (joins all-systems, report swallowed by the drop
// output). Returns its pointer for etharp_find_addr assertions.
struct netif *addStubEthernetNetif() {
    ip4_addr_t ip;
    ip4_addr_t nm;
    ip4_addr_t gw;
    IP4_ADDR(&ip, 192, 168, 50, 1);
    IP4_ADDR(&nm, 255, 255, 255, 0);
    IP4_ADDR(&gw, 192, 168, 50, 1);
    LOCK_TCPIP_CORE();
    netif_add(&g_stub, &ip, &nm, &gw, nullptr, stubNetifInit, tcpip_input);
    netif_set_default(&g_stub);
    netif_set_link_up(&g_stub);
    netif_set_up(&g_stub);
    UNLOCK_TCPIP_CORE();
    return &g_stub;
}

// Make lwIP LEARN an entry, the way the tester's entry is learned on the wire: an
// ARP Reply from `sender_be` / `sender_mac` to the stub's own address, handed to
// ethernet_input under the core lock. etharp_input records it as a STABLE entry.
void learnFromArpReply(struct netif *nif, std::uint32_t sender_be, const std::uint8_t sender_mac[6]) {
    struct pbuf *p = pbuf_alloc(PBUF_RAW, SIZEOF_ETH_HDR + SIZEOF_ETHARP_HDR, PBUF_RAM);
    if (p == nullptr) {
        check(false, "pbuf_alloc for the ARP Reply");
        return;
    }
    std::uint8_t *f = static_cast<std::uint8_t *>(p->payload);
    std::memcpy(f, nif->hwaddr, 6);           // Ethernet destination: the stub
    std::memcpy(f + 6, sender_mac, 6);        // Ethernet source: the sender
    f[12] = 0x08;
    f[13] = 0x06;                             // EtherType ARP
    const std::uint8_t arp_fixed[8] = {0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02};  // Ethernet/IPv4, Reply
    std::memcpy(f + 14, arp_fixed, sizeof(arp_fixed));
    std::memcpy(f + 22, sender_mac, 6);       // sender hardware address
    std::memcpy(f + 28, &sender_be, 4);       // sender protocol address
    std::memcpy(f + 32, nif->hwaddr, 6);      // target hardware address
    const std::uint32_t target_be = ip4_addr_get_u32(netif_ip4_addr(nif));
    std::memcpy(f + 38, &target_be, 4);       // target protocol address
    LOCK_TCPIP_CORE();
    if (ethernet_input(p, nif) != ERR_OK) {
        pbuf_free(p);
    }
    UNLOCK_TCPIP_CORE();
}

bool staticEntryPresent(struct netif *nif, std::uint32_t addr_be) {
    ip4_addr_t ip{};
    ip4_addr_set_u32(&ip, addr_be);
    LOCK_TCPIP_CORE();
    struct eth_addr *eth_ret = nullptr;
    const ip4_addr_t *ip_ret = nullptr;
    const bool found = etharp_find_addr(nif, &ip, &eth_ret, &ip_ret) >= 0;
    UNLOCK_TCPIP_CORE();
    return found;
}

// True if `nif` currently holds an IGMP membership for `group_be` — the multicast
// analog of staticEntryPresent, so the join/leave tests observe the actual group
// state, not just the setsockopt return code.
bool groupJoined(struct netif *nif, std::uint32_t group_be) {
    ip4_addr_t group{};
    ip4_addr_set_u32(&group, group_be);
    LOCK_TCPIP_CORE();
    const bool joined = igmp_lookfor_group(nif, &group) != nullptr;
    UNLOCK_TCPIP_CORE();
    return joined;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    bringUpStack();
    struct netif *stub = addStubEthernetNetif();

    // lwIP assigns netif->num from a global counter, so with the loopback netif
    // already present the stub is "st1", not "st0"; build the name from its num.
    const std::string ifname = "st" + std::to_string(stub->num);

    tc8::lwip_dut::LwipSocketBackend be;

    // 1) Multicast join/leave on an IGMP-capable netif — assert the membership
    //    actually lands and is dropped, not just that setsockopt returned 0.
    const int sock = be.createUdp();
    check(sock >= 0, "createUdp");
    const std::uint32_t group_be = PP_HTONL(0xEF010203);  // 239.1.2.3 (admin-scoped)
    check(!groupJoined(stub, group_be), "group not joined before join");
    checkStatus(be.joinMulticast(sock, group_be, 0), tc8::net::OpStatus::Ok,
                "joinMulticast on IGMP netif (default iface)");
    check(groupJoined(stub, group_be), "IGMP membership present after join");
    checkStatus(be.leaveMulticast(sock, group_be, 0), tc8::net::OpStatus::Ok,
                "leaveMulticast on IGMP netif");
    check(!groupJoined(stub, group_be), "IGMP membership gone after leave");
    be.closeFd(sock);

    // 2) Static ARP add / find / idempotent remove on the stub's subnet.
    const std::uint32_t nbr_be = PP_HTONL(0xC0A83202);  // 192.168.50.2 (on the stub's /24)
    const std::uint8_t mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    check(!staticEntryPresent(stub, nbr_be), "no static entry before add");
    checkStatus(be.addStaticNeighbor(ifname, nbr_be, mac), tc8::net::OpStatus::Ok,
                "addStaticNeighbor on stub netif");
    check(staticEntryPresent(stub, nbr_be), "static entry present after add");
    checkStatus(be.removeNeighbor(ifname, nbr_be), tc8::net::OpStatus::Ok,
                "removeNeighbor removes the entry");
    check(!staticEntryPresent(stub, nbr_be), "static entry gone after remove");
    checkStatus(be.removeNeighbor(ifname, nbr_be), tc8::net::OpStatus::Ok,
                "removeNeighbor is idempotent (absent => Ok)");

    // 2b) A LEARNED entry, the kind the tester's own entry is once it has pinged the
    //     DUT. lwIP removes only a static entry by address; the backend makes the
    //     learned one static first and must then remove it like any other.
    const std::uint32_t learned_be = PP_HTONL(0xC0A83203);  // 192.168.50.3
    const std::uint8_t learned_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    learnFromArpReply(stub, learned_be, learned_mac);
    check(staticEntryPresent(stub, learned_be), "learned entry present after the ARP Reply");
    checkStatus(be.removeNeighbor(ifname, learned_be), tc8::net::OpStatus::Ok,
                "removeNeighbor removes a learned entry");
    check(!staticEntryPresent(stub, learned_be), "learned entry gone after remove");

    // 2c) recvFromV4 answers the datagram's WHOLE length (tc8/net/socket_backend.h):
    //     a 200-byte datagram read into a 64-byte buffer is 200, its first 64 bytes in
    //     the buffer. lwIP's recvfrom alone answers the 64 it copied.
    {
        const std::uint32_t loop_be = PP_HTONL(0x7F000001);  // 127.0.0.1
        const int rx = be.createUdp();
        const int tx = be.createUdp();
        check(rx >= 0 && tx >= 0, "createUdp for the length check");
        check(be.bindV4(rx, loop_be, 40123), "bind the receiver on loopback");
        be.setRecvTimeoutMs(rx, 2000);
        std::uint8_t datagram[200];
        for (std::size_t i = 0; i < sizeof(datagram); ++i) {
            datagram[i] = static_cast<std::uint8_t>(i);
        }
        tc8::net::Endpoint to{};
        to.addr_be = loop_be;
        to.port = 40123;
        check(be.sendToV4(tx, datagram, sizeof(datagram), to) == static_cast<int>(sizeof(datagram)),
              "send a 200-byte datagram");
        std::uint8_t buf[64] = {};
        tc8::net::Endpoint from{};
        const int n = be.recvFromV4(rx, buf, sizeof(buf), from);
        check(n == static_cast<int>(sizeof(datagram)), "recvFromV4 answers the whole length (200)");
        check(std::memcmp(buf, datagram, sizeof(buf)) == 0, "the first 64 bytes are in the buffer");
        check(from.port != 0, "the source is filled");
        be.closeFd(rx);
        be.closeFd(tx);
    }

    // 2c') A TCP socket whose pcb lwIP freed reads as CLOSED, as Linux's TCP_INFO does:
    //      a connect to a loopback port nobody listens on is answered with a RST, lwIP
    //      frees the TCB and keeps the socket.
    {
        const int s = be.createTcp();
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = lwip_htons(40124);
        to.sin_addr.s_addr = PP_HTONL(0x7F000001);
        const int rc = lwip_connect(s, reinterpret_cast<sockaddr *>(&to), sizeof(to));
        check(rc != 0, "connect to a closed loopback port is refused");
        tc8::net::TcpInfo info{};
        info.state = 0xFF;
        tc8::lwip_dut::LwipTcpInfoReader reader;
        check(reader.queryTcpInfo(s, info), "the reader reports a socket whose pcb is gone");
        check(info.state == tc8::net::kTcpStateClose, "and reports it CLOSED");
        be.closeFd(s);
    }

    // 2d) Don't Fragment: clear is how every packet lwIP originates already leaves, so
    //     a request to clear it is E_OK; one to set it is E_NTF.
    {
        const int s = be.createUdp();
        const std::uint8_t clear = 0;
        const std::uint8_t set = 1;
        check(be.configureOption(s, tc8::testability::kCfgDontFragment, &clear, 1) ==
                  tc8::testability::kRidEOk,
              "configureOption DF=0 is E_OK");
        check(be.configureOption(s, tc8::testability::kCfgDontFragment, &set, 1) ==
                  tc8::testability::kRidENtf,
              "configureOption DF=1 is E_NTF");
        be.closeFd(s);
    }

    // 3) Contract edges, and the reason this seam answers a status rather than a
    //    bool: an unknown interface, an argument the seam cannot honor, and a
    //    capability lwIP does not have are THREE different answers on this stack.
    //    Collapsed to `false` a test system could not tell an operator's typo from
    //    a permanent property of the target.
    checkStatus(be.addStaticNeighbor("tc8_no_such", nbr_be, mac),
                tc8::net::OpStatus::UnknownInterface, "addStaticNeighbor unknown iface");
    checkStatus(be.removeNeighbor("tc8_no_such", nbr_be), tc8::net::OpStatus::UnknownInterface,
                "removeNeighbor unknown iface");
    checkStatus(be.addStaticNeighbor(ifname, nbr_be, nullptr),
                tc8::net::OpStatus::InvalidArgument, "addStaticNeighbor null MAC");
    // Runtime ARP aging is a fixed ARP_MAXAGE on lwIP: Unsupported, not Failed —
    // no privilege and no argument makes it work here, which is precisely what a
    // tester needs to learn without reading this file.
    checkStatus(be.setNeighborReachableMs(ifname, 30000), tc8::net::OpStatus::Unsupported,
                "setNeighborReachableMs unsupported on lwIP");
    checkStatus(be.flushDynamicArp(ifname), tc8::net::OpStatus::Unsupported,
                "flushDynamicArp unsupported on lwIP (no per-netif etharp flush)");

    if (g_failures == 0) {
        std::fprintf(stderr, "lwip_arp_multicast_test: PASS\n");
        return 0;
    }
    std::fprintf(stderr, "lwip_arp_multicast_test: %d FAILURE(S)\n", g_failures);
    return 1;
}
