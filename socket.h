#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <thread>
#include "get_info.h"
#include "arp_spoof.h"

static const int BUF_SIZE=1024;

bool connect_sock(int * client_sock, int server_port);
bool send_data(int client_sock, char *data);
bool recv_data(int client_sock, char *data);
void print_ip(uint32_t ip);
void print_MAC(uint8_t *addr);
void scan_pkt_send(Info info, Arp find_dev_arp, int client_fd);
void scan_pkt_check(Info info, uint32_t ip, int client_fd);
void attack(pcap_t* handle, Arp arp, int client_fd);
