#pragma once
#include <stdint.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <pcap.h>
#define BUFSIZE 8192

struct route_info{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

class Info{
public:
    uint32_t gw_ip;
    uint8_t gw_mac[6];
    uint32_t ip;
    char iface_name[10];
    uint32_t subnet;
    uint8_t attacker_mac[6];
    void save_iface_name();
    void save_gw_ip();
    void save_gw_mac(char * dev);
    void save_my_ip();
    void save_my_mac(char * dev);
    void print_mac(uint8_t *mac);
    void print_ip(uint32_t ip);
};