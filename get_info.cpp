#include "get_info.h"

void Info::save_iface_name(){
    // interface name
    FILE * stream = popen("getprop wifi.interface", "r");
    fgets(this->iface_name, 10, stream);
    pclose(stream);
    for(int i = 0; ; i++){
        if(this->iface_name[i] == '\n'){
            this->iface_name[i] = 0;
            printf("%s\n", this->iface_name);
            break;
        }
    }
}
void Info::save_gw_ip(){
    // gateway ip
    char output[50] = {0,};
    FILE * stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 50, stream);

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr){
        if(i == 2){
            this->gw_ip = inet_addr(ptr);
            return;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
}

void Info::save_my_ip(){
    char output[80] = {0,};
    FILE * stream = popen("ip route get 8.8.8.8", "r");

    fgets(output, 80, stream);

    char *ptr = strtok(output, " ");
    int i = 0;
    while (ptr != nullptr){
        if(i == 6){
            this->ip = inet_addr(ptr);
            return;
        }
        i++;
        ptr = strtok(nullptr, " ");
    }
}
void Info::save_my_mac(char * dev){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) perror("socket fail");
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");
    unsigned char * tmp = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);

    memcpy(this->attacker_mac, tmp, sizeof(uint8_t)*6);
}

void Info::print_mac(uint8_t *mac){
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

void Info::print_ip(uint32_t ip){
    printf("%d.%d.%d.%d\n", (ip)&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF);
}