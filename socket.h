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
void scan_pkt_send(int client_fd);
void scan_pkt_check(uint32_t ip, int client_fd);
