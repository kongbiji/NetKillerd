#pragma once
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>

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

struct info{
    char name[10];
    char desc[40];
    pcap_if_t * dev{nullptr};
    uint32_t ip;
    uint32_t subnetmask;
    uint32_t gateway;
    uint32_t ip_and_mask;
};
#pragma pack(pop)

class Arp{
private:
    
public:
    uint32_t target_ip;
    uint8_t target_mac[6];
    uint32_t sender_ip;
    uint8_t sender_mac[6]; // attacker's MAC
    char dev[10];
    u_char attack_pkt[sizeof(ARP_Packet)];
    u_char pkt[sizeof(ARP_Packet)];
    Arp();
    void make_arp_packet(uint8_t *target_mac, uint8_t *src_mac, int op, uint32_t sender_ip, uint32_t target_ip, ARP_Packet * packet);
    void start_attack(pcap_t* handle, char * data);
    void stop_attack(pcap_t* handle, char * data);
};