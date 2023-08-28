#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int soc;
    struct ifreq ifr;
    struct sockaddr_ll addr;
    char buf[2048];
    char *ifname;
    ssize_t n;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ifname\n", argv[0]);
        return -1;
    }

    soc = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (soc == -1) {
        perror("socket");
        return -1;
    }

    ifname = argv[1];
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl [SIOCGIFINDEX]");
        close(soc);
        return -1;
    }

    memset(&addr, 0x00, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(soc);
        return -1;
    }
    while (1) {
        /* ソケットからデータ受信 */
        n = recv(soc, buf, sizeof(buf), 0);
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            close(soc);
            return -1;
        }
        printf("recv: %zd bytes via %s\n", n, ifname);
    }
    close(soc);
    return 0;
}
