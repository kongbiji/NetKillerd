#pragma once
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <map>

#pragma pack(push,1)
typedef struct {
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
}Ether;

typedef struct {
    uint16_t hw_type;
    uint16_t p_type;
    uint8_t hw_len;
    uint8_t p_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
}ARP;

typedef struct {
    Ether eth;
    ARP arp;
}ARP_Packet;

typedef struct {
    char name[10];
    char desc[40];
    pcap_if_t * dev{nullptr};
    uint32_t ip;
    uint32_t subnetmask;
    uint32_t gateway;
    uint32_t ip_and_mask;
}info;

typedef struct {
    uint8_t mac[6];
    uint32_t ip;
    char iface_name[10];
}GW_info;

typedef struct {
    uint8_t mac[6];
    uint32_t ip;
}ATTACKER_info;

typedef struct {
    uint8_t victim_mac[6];
    uint32_t victim_ip;
    uint8_t attacker_mac[6];
    uint32_t attacker_ip;
    volatile bool is_attack;

    u_char attack_pkt[sizeof(ARP_Packet)];

    pcap_t * handle;

}DEV_info;

typedef struct MAC{
    uint8_t mac[6];
    bool operator <(const MAC& var) const
    {
        return memcmp(mac, var.mac, sizeof(mac)) < 0;
    }
} MAC;

#pragma pack(pop)

void make_arp_packet(uint8_t *target_mac, uint8_t *src_mac, int op, uint32_t sender_ip, uint32_t target_ip, ARP_Packet * packet);