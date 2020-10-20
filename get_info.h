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
#include <map>
#include "arp_spoof.h"
#define BUFSIZE 8192

struct route_info{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

void save_iface_name(char * iface_name);
void save_gw_ip(uint32_t * gw_ip);
void save_gw_mac(char * dev, uint8_t * gw_mac);
void save_my_ip(uint32_t * ip);
void save_my_mac(char * dev, uint8_t * mac);
void print_mac(uint8_t *mac);
void print_ip(uint32_t ip);