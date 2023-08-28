#include "ip.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arp.h"
#include "net.h"
#include "platform.h"
#include "util.h"

struct ip_hdr {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src,
                    ip_addr_t dst, struct ip_iface *iface);
};

struct ip_route {
    struct ip_route *next;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct ip_iface *iface;
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;
static struct ip_route *routes;

int ip_addr_pton(const char *p, ip_addr_t *n) {
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if ((ret < 0) || (ret > 255)) return -1;
        if (ep == sp) return -1;
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) return -1;

        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *ip_addr_ntop(ip_addr_t n, char *p, size_t size) {
    uint8_t *u8;
    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

int ip_endpoint_pton(const char *p, struct ip_endpoint *n) {
    char *sep;
    char addr[IP_ADDR_STR_LEN] = {};
    long int port;

    sep = strrchr(p, ':');
    if (!sep) {
        return -1;
    }
    memcpy(addr, p, sep - p);
    if (ip_addr_pton(addr, &n->addr) == -1) {
        return -1;
    }
    port = strtol(sep + 1, NULL, 10);
    if (port <= 0 || port > UINT16_MAX) {
        return -1;
    }
    n->port = hton16(port);
    return 0;
}

char *ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size) {
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

static void ip_dump(const uint8_t *data, size_t len) {
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char src[IP_ADDR_STR_LEN], dst[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    total = ntoh16(hdr->total);
    offset = ntoh16(hdr->offset);

    fprintf(stderr,
            "     vhl: 0x%02x [v: %u, hl: %u (%u)]\n"
            "     tos: 0x%02x\n"
            "   total: %u (payload: %u)\n"
            "      id: %u\n"
            "  offset: 0x%04x [flags=%x, offset=%u]\n"
            "     ttl: %u\n"
            "protocol: %u\n"
            "     sum: 0x%04x\n"
            "     src: %s\n"
            "     dst: %s\n",
            hdr->vhl, v, hl, hlen, hdr->tos, total, total - hlen,
            ntoh16(hdr->id), offset, (offset & 0xe000) >> 13, offset & 0x1fff,
            hdr->ttl, hdr->protocol, ntoh16(hdr->sum),
            ip_addr_ntop(hdr->src, src, sizeof(src)),
            ip_addr_ntop(hdr->dst, dst, sizeof(dst)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
}

/* NOTE: must not be call after net_run() */
static struct ip_route *ip_route_add(ip_addr_t network, ip_addr_t netmask,
                                     ip_addr_t nexthop,
                                     struct ip_iface *iface) {
    struct ip_route *route;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];

    route = memory_alloc(sizeof(struct ip_route));

    if (!route) {
        errorf("memory_alloc() failure");
        return NULL;
    }

    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;

    route->next = routes;
    routes = route;

    infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s",
          ip_addr_ntop(route->network, addr1, sizeof(addr1)),
          ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
          ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
          NET_IFACE(iface)->dev->name);
    return route;
}

static struct ip_route *ip_route_lookup(ip_addr_t dst) {
    struct ip_route *route, *candidate = NULL;

    for (route = routes; route; route = route->next) {
        if ((dst & route->netmask) == route->network) {
            if (!candidate ||
                ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
    }
    return candidate;
}

/* NOTE: must not be call after net_run() */
int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway) {
    ip_addr_t gw;
    if (ip_addr_pton(gateway, &gw) == -1) {
        errorf("ip_addr_pton() failure,Addr=%s", gateway);
        return -1;
    }
    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }
    return 0;
}

struct ip_iface *ip_route_get_iface(ip_addr_t dst) {
    struct ip_route *route;

    route = ip_route_lookup(dst);
    if (!route) {
        return NULL;
    }
    return route->iface;
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    if (ip_addr_pton(unicast, &iface->unicast)) {
        errorf("convert unicast failure");
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask)) {
        errorf("convert netmask failure");
        memory_free(iface);
        return NULL;
    }
    iface->broadcast = (iface->unicast & iface->netmask) | ~(iface->netmask);

    return iface;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    if (net_device_add_iface(dev, (struct net_iface *)iface)) {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    if (!ip_route_add(iface->unicast & iface->netmask, iface->netmask,
                      IP_ADDR_ANY, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }

    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr) {
    struct ip_iface *entry;
    for (entry = ifaces; entry; entry = ifaces->next) {
        if (entry->unicast == addr) return entry;
    }
    return NULL;
}

int ip_protocol_register(uint8_t type,
                         void (*handler)(const uint8_t *data, size_t len,
                                         ip_addr_t src, ip_addr_t dst,
                                         struct ip_iface *iface)) {
    struct ip_protocol *proto;
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            errorf("already registered, type=%u", type);
            return -1;
        }
    }
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }
    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registred, type=%u", type);
    return 0;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct ip_hdr *hdr;
    uint8_t v, type;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    v = ((hdr->vhl & 0xf0) >> 4);
    hlen = (hdr->vhl & 0x0f) << 2;
    type = hdr->protocol;
    total = ntoh16(hdr->total);

    if (v != IP_VERSION_IPV4) {
        errorf("wrong version");
        return;
    }
    if (len < hlen) {
        errorf("too short len than header length");
        return;
    }
    if (len < total) {
        errorf("too short len than total length");
        return;
    }
    if (cksum16((uint16_t *)hdr, hlen, 0) != 0) {
        errorf("wrong checksum");
        return;
    }

    offset = ntoh16(hdr->offset);
    if ((offset & 0x2000) || (offset & 0x1fff)) {
        errorf("fragments does not support");
        return;
    }

    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface) return;

    if (((hdr->dst) != iface->unicast) && ((hdr->dst) != iface->unicast) &&
        ((hdr->dst) != IP_ADDR_BROADCAST))
        return;

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name,
           ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol,
           total);
    ip_dump(data, total);

    for (struct ip_protocol *proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            proto->handler(data + hlen, len - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data,
                            size_t len, ip_addr_t dst) {
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast,
                   NET_IFACE(iface)->dev->alen);
        } else {
            ret = arp_resolve((struct net_iface *)iface, dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND) return ret;
        }
    }

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data,
                             len, hwaddr);
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol,
                              const uint8_t *data, size_t len, ip_addr_t src,
                              ip_addr_t dst, ip_addr_t nexthop, uint16_t id,
                              uint16_t offset) {
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;
    hlen = IP_HDR_SIZE_MIN;
    total = hlen + len;

    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xFF;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;

    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);

    memcpy(buf + hlen, data, len);
    debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name,
           ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);

    return ip_output_device(iface, buf, total, nexthop);
}

static uint16_t ip_generate_id(void) {
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len,
                  ip_addr_t src, ip_addr_t dst) {
    struct ip_iface *iface;
    struct ip_route *route;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;
    ip_addr_t nexthop;

    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
        errorf("source address is required for broadcast addresses");
        return -1;
    }
    route = ip_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s",
               ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }

    iface = route->iface;
    if (!iface) {
        errorf("src interface not found, src=%s",
               ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }

    if (src != IP_ADDR_ANY && src != iface->unicast) {
        errorf("unable to output with specified source address, addr=%s",
               ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;

    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name,
               NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop,
                       id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
}

int ip_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}