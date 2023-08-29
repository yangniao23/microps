
#include "arp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "ether.h"
#include "ip.h"
#include "net.h"
#include "platform.h"
#include "util.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TIMEOUT 30 /* seconds */

#define ARP_CACHE_STATE_FREE 0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED 2
#define ARP_CACHE_STATE_STATIC 3

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};
struct arp_cache {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

static char *arp_opcode_ntoa(uint16_t opcode) {
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    char sha[ETHER_ADDR_STR_LEN], tha[ETHER_ADDR_STR_LEN];
    char spa_s[IP_ADDR_STR_LEN], tpa_s[IP_ADDR_STR_LEN];

    msg = (struct arp_ether_ip *)data;
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    fprintf(stderr,
            "hrd: 0x%04x\n"
            "pro: 0x%04x\n"
            "hln: %u\n"
            "pln: %u\n"
            " op: %u (%s)\n"
            "sha: %s\n"
            "spa: %s\n"
            "tha: %s\n"
            "tpa: %s\n",
            ntoh16(msg->hdr.hrd), ntoh16(msg->hdr.pro), msg->hdr.hln,
            msg->hdr.pln, ntoh16(msg->hdr.op), arp_opcode_ntoa(msg->hdr.op),
            ether_addr_ntop(msg->sha, sha, sizeof(sha)),
            ip_addr_ntop(spa, spa_s, sizeof(spa_s)),
            ether_addr_ntop(msg->tha, tha, sizeof(tha)),
            ip_addr_ntop(tpa, tpa_s, sizeof(tpa_s)));
}

/*
 * ARP Cache
 *
 * NOTE: ARP Cache functions must be called after mutex locked
 */

static void arp_cache_delete(struct arp_cache *cache) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s",
           ip_addr_ntop(cache->pa, addr1, sizeof(addr1)),
           ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = IP_ADDR_ANY;
    memcpy(cache->ha, ETHER_ADDR_ANY, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

static struct arp_cache *arp_cache_alloc(void) {
    struct arp_cache *entry, *oldset = NULL;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) return entry;

        if (!oldset || timercmp(&oldset->timestamp, &entry->timestamp, >))
            oldset = entry;
    }
    arp_cache_delete(oldset);
    return oldset;
}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {
    struct arp_cache *entry;
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) continue;
        if (entry->pa == pa) return entry;
    }
    return NULL;
}

static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_select(pa);
    if (!cache) return NULL;

    cache->state = ARP_CACHE_STATE_RESOLVED;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_alloc();
    if (!cache) return NULL;

    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}
static int arp_request(struct net_iface *iface, ip_addr_t tpa) {
    struct arp_ether_ip req;

    req.hdr.hrd = hton16(ARP_HRD_ETHER);
    req.hdr.pro = hton16(ARP_PRO_IP);
    req.hdr.hln = ETHER_ADDR_LEN;
    req.hdr.pln = IP_ADDR_LEN;
    req.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(req.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(req.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(req.tha, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
    memcpy(req.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(req));
    arp_dump((uint8_t *)&req, sizeof(req));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&req,
                             sizeof(req), iface->dev->broadcast);
}

static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa,
                     const uint8_t *dst) {
    struct arp_ether_ip reply;

    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply,
                             sizeof(reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int marge = 0;  // キャッシュ済みなら更新して 1 になる

    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;

    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER ||
        msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("unsupported hardware address");
        return;
    }
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("unsupported protocol address");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    mutex_lock(&mutex);
    if (arp_cache_update(spa, msg->sha)) marge = 1;
    mutex_unlock(&mutex);

    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (!marge) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
            if (arp_reply(iface, msg->sha, spa, msg->sha) == -1) {
                errorf("arp_reply() failure");
                return;
            }
        }
    }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    if (!cache) {
        debugf("cache not found, pa=%s",
               ip_addr_ntop(pa, addr1, sizeof(addr1)));

        cache = arp_cache_alloc();
        if (!cache) {
            errorf("arp_cache_alloc() failure");
            return ARP_RESOLVE_ERROR;
        }

        cache->state = ARP_RESOLVE_INCOMPLETE;
        cache->pa = pa;
        gettimeofday(&cache->timestamp, NULL);

        mutex_unlock(&mutex);

        arp_request(iface, pa);
        return ARP_RESOLVE_INCOMPLETE;
    }
    if (cache->state == ARP_RESOLVE_INCOMPLETE) {
        mutex_unlock(&mutex);
        arp_request(iface, pa);
        return ARP_RESOLVE_INCOMPLETE;
    }
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

static void arp_timer_handler(void) {
    struct arp_cache *entry;
    struct timeval now, diff;

    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE &&
            entry->state != ARP_CACHE_STATE_STATIC) {
            timersub(&now, &entry->timestamp, &diff);
            if (diff.tv_sec >= ARP_CACHE_TIMEOUT) {
                arp_cache_delete(entry);
            }
        }
    }
    mutex_unlock(&mutex);
}

int arp_init(void) {
    struct timeval interval = {1, 0};
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    if (net_timer_register(interval, arp_timer_handler) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}
