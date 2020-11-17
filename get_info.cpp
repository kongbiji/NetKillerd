#include "get_info.h"

extern GW_info gw_info;
extern ATTACKER_info attacker_info;

extern DEV_info ap_info;
extern std::map<MAC, DEV_info> dev_list;

void save_iface_name(char * iface_name)
{
    // interface name
    FILE *stream = popen("getprop wifi.interface", "r");
    fgets(iface_name, 10, stream);
    pclose(stream);
    for (int i = 0;; i++)
    {
        if (iface_name[i] == '\n')
        {
            iface_name[i] = 0;
            break;
        }
    }
}
void save_gw_ip(uint32_t * gw_ip)
{
    // gateway ip
    char output[50] = {
        0,
    };
    FILE *stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 50, stream);

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr)
    {
        if (i == 2)
        {
            *gw_ip = inet_addr(ptr);
            return;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
}

void save_gw_mac(char *dev, uint8_t *gw_mac)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(gw_info.iface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("[-] cannot open pcap handle\n");
        exit(1);
    }
    uint8_t broad_mac[6];
    memset(broad_mac, 0xff, sizeof(uint8_t)*6);

    // to restore arp table, we need gw mac address
    ARP_Packet * arp_data = (ARP_Packet *)malloc(sizeof(ARP_Packet));
    memset(arp_data, 0, sizeof(ARP_Packet));
    make_arp_packet(broad_mac, attacker_info.mac, 0x1, attacker_info.ip, gw_info.ip, arp_data, false);

    u_char pkt[sizeof(ARP_Packet)];
    memcpy(pkt, arp_data, sizeof(ARP_Packet));

    if (pcap_sendpacket(handle, pkt, sizeof(ARP_Packet)) != 0)
    {
        printf("[-] couldn't send attack pkt\n");
        return;
    }

    ARP_Packet *arp_packet;
    struct pcap_pkthdr *header;
    const u_char *rep;

    while (1)
    { //check correct arp reply
        pcap_next_ex(handle, &header, &rep);
        arp_packet = (ARP_Packet *)rep;
        if ((arp_packet->arp.sender_ip == gw_info.ip) && (ntohs(arp_packet->arp.opcode) == 2))
        {
            memcpy(gw_info.mac, arp_packet->eth.src_MAC, sizeof(gw_info.mac));
            break;
        }
    }
    pcap_close(handle);
}

void save_my_ip(uint32_t *ip)
{
    char output[80] = {
        0,
    };
    FILE *stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 80, stream);

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr)
    {
        if (i == 6)
        {
            *ip = inet_addr(ptr);
            return;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
}
void save_my_mac(char *dev, uint8_t *mac)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    unsigned char *tmp = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);

    memcpy(mac, tmp, sizeof(uint8_t) * 6);
}

uint32_t get_subnet(char * dev)
{
    int sock;
    struct ifreq ifr;
    struct sockaddr_in *sin;

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        return 0;
    }


    strcpy(ifr.ifr_name, dev);
    if (ioctl(sock, SIOCGIFNETMASK, &ifr)< 0)
    {
        close(sock);
        return 0;
    }

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    uint32_t subnet_mask = sin->sin_addr.s_addr;
    close(sock);

    return subnet_mask;
}

void print_mac(uint8_t *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint32_t ip)
{
    printf("%d.%d.%d.%d\n", (ip)&0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}