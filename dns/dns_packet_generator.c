#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>

#define DNS_PORT            53
#define UDP_HEADER_LENGTH   8
#define DNS_HEADER_LENGTH   12
#define DNS_QUERY_TYPE_A    0x0001   // QTYPE A
#define DNS_CLASS_IN        0x0001   // QCLASS IN

// Structure for DNS header
struct DnsHeader {
    uint16_t id;                // Identifier (transaction id)
    uint16_t flags;             // Flags
    uint16_t qdCount;           // Number of Questions
    uint16_t anCount;           // Number of Answers
    uint16_t nsCount;           // Number of Authority RRs
    uint16_t arCount;           // Number of Additional RRs
};

// Function to retrieve the MAC address of the specified interface
int getMacAddress(const char *iface, uint8_t *mac) {
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        // SIOCGIFHWADDR(getting or setting hardware address) is used to get the MAC address of the interface
        perror("ioctl");
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

// DNS query for an A(IPv4) record
void buildDnsQuery(uint8_t *dnsQuery, const char *hostname) {
    struct DnsHeader *dnsHeader = (struct DnsHeader *)dnsQuery;
    dnsHeader->id = htons(rand() & 0xFFFF);
    dnsHeader->flags = htons(0x0100); // Standard Query
    dnsHeader->qdCount = htons(1);    // One question
    dnsHeader->anCount = 0;
    dnsHeader->nsCount = 0;
    dnsHeader->arCount = 0;

    uint8_t *qname = dnsQuery + sizeof(struct DnsHeader);

    // Convert the hostname to DNS format
    // example)
    //  - www.example.com -> 3www7example3com0
    //  - ap-northeast.compoute.amazonaws.com -> 2ap10northeast7compute9amazonaws3com0
    const char *label = hostname;
    while (*label) {
        const char *nextLabel = strchr(label, '.');
        int labelLength = nextLabel ? nextLabel - label : strlen(label);
        if (labelLength > 63) {
            fprintf(stderr, "Label length exceeds 63 characters.\n");
            exit(EXIT_FAILURE);
        }
        *qname++ = labelLength;
        strncpy((char *)qname, label, labelLength);
        qname += labelLength;
        label += labelLength + 1;
    }
    *qname++ = 0; // End of the domain Name

    // Set QTYPE and QCLASS for A(IPv4) record, IN Class
    *(uint16_t *)qname = htons(DNS_QUERY_TYPE_A);
    qname += 2;
    *(uint16_t *)qname = htons(DNS_CLASS_IN);
}

// Function to compute IP checksum
// 1. Add all 16-bit words in the header
// 2. Fold the 32-bit sum to 16 bits
// 3. Take the one's complement of the sum
// 4. Return the checksum
unsigned short computeIpChecksum(struct ip *ipHeader) {
    unsigned long sum = 0;
    unsigned short *ptr = (unsigned short *)ipHeader;
    for (int i = 0; i < (ipHeader->ip_hl * 2); i++) {
        sum += ntohs(ptr[i]);
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(~sum);
}

// Function to compute UDP checksum (optional)
// 1. Create a pseudo header with source and destination IP addresses, protocol, and UDP labelLength
// 2. Add all 16-bit words in the pseudo header
// 3. Add all 16-bit words in the UDP header
// 4. Add all 16-bit words in the payload
// 5. Fold the 32-bit sum to 16 bits
// 6. Take the one's complement of the sum
// 7. Return the checksum
unsigned short computeUdpChecksum(struct ip *ipHeader, struct udphdr *udpHeader, uint8_t *payload, int payloadLen) {
    unsigned long sum = 0;
    struct {
        uint32_t srcAddr;
        uint32_t dstAddr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udpLength;
    } pseudoHeader;

    pseudoHeader.srcAddr = ipHeader->ip_src.s_addr;
    pseudoHeader.dstAddr = ipHeader->ip_dst.s_addr;
    pseudoHeader.zero = 0;
    pseudoHeader.protocol = IPPROTO_UDP;
    pseudoHeader.udpLength = udpHeader->len;

    uint16_t *ptr = (uint16_t *)&pseudoHeader;
    for (int i = 0; i < sizeof(pseudoHeader)/2; i++) {
        sum += ntohs(ptr[i]);
    }

    ptr = (uint16_t *)udpHeader;
    for (int i = 0; i < 4; i++) { // 4 * 16-bit words in UDP header
        sum += ntohs(ptr[i]);
    }

    ptr = (uint16_t *)payload;
    for (int i = 0; i < (payloadLen / 2); i++) {
        sum += ntohs(ptr[i]);
    }
    if (payloadLen % 2) {
        sum += ntohs(((uint8_t)payload[payloadLen - 1]) << 8);
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons(~sum);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <hostname>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *interface = argv[1];
    char hostname[256];
    strncpy(hostname, argv[2], sizeof(hostname) - 1);
    hostname[sizeof(hostname) - 1] = '\0';
    printf("Sending DNS query for %s via interface %s\n", hostname, interface);

    srand(time(NULL));

    // Get the MAC address of the interface
    uint8_t srcMac[6];
    if (getMacAddress(interface, srcMac) != 0) {
        fprintf(stderr, "Failed to get MAC address for interface %s\n", interface);
        return EXIT_FAILURE;
    }

    // Get the IPv4 address of the interface
    char srcIpStr[INET_ADDRSTRLEN];
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return EXIT_FAILURE;
    }

    int found = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (strcmp(ifa->ifa_name, interface) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            // Found the IPv4 address for the interface
            // Convert the binary address to a string
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            // inet_ntop() converts the network address structure src to a string in the specified address family
            inet_ntop(AF_INET, &(sa->sin_addr), srcIpStr, INET_ADDRSTRLEN);
            found = 1;
            break;
        }
    }
    freeifaddrs(ifaddr);
    if (!found) {
        fprintf(stderr, "Could not find IPv4 address for interface %s\n", interface);
        return EXIT_FAILURE;
    }

    // Open the packet capture interface
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errorBuffer);
    if (!handle) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errorBuffer);
        return EXIT_FAILURE;
    }

    // Build the DNS query
    uint8_t dnsQuery[512];
    buildDnsQuery(dnsQuery, hostname);
    int dnsQueryLength = sizeof(struct DnsHeader);

    const char *label = hostname;
    while (*label) {
        const char *nextLabel = strchr(label, '.');
        int labelLength = nextLabel ? nextLabel - label : strlen(label);
        dnsQueryLength += 1 + labelLength;
        label += labelLength + 1;
    }
    dnsQueryLength += 1; // Null byte
    dnsQueryLength += 2; // QTYPE
    dnsQueryLength += 2; // QCLASS

    // Build the DNS packet (Ethernet(layer 2) -> IP(layer 3) -> UDP(layer 4) -> DNS(layer 7))
    int packetSize = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + dnsQueryLength;
    uint8_t *packet = malloc(packetSize);
    if (!packet) {
        fprintf(stderr, "Memory allocation failed\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    memset(packet, 0, packetSize);

    // Build the Ethernet header, building a broadcast frame, encapsulating an IP packet
    struct ether_header *ethernetHeader = (struct ether_header *)packet;
    memset(ethernetHeader->ether_dhost, 0xff, 6); // Destination MAC: Broadcast(FF-FF-FF-FF-FF-FF)
    memcpy(ethernetHeader->ether_shost, srcMac, 6); // Source MAC (from the interface)
    ethernetHeader->ether_type = htons(ETHERTYPE_IP);

    // Build the IP header
    struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    ipHeader->ip_v = 4;
    ipHeader->ip_hl = 5;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + dnsQueryLength);
            // Total length of the IP Packet (IP and upper layer)
            // IP Header + UDP Header + DNS Query
    ipHeader->ip_id = htons(rand() & 0xFFFF);
    ipHeader->ip_off = 0;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = IPPROTO_UDP;
    inet_pton(AF_INET, srcIpStr, &ipHeader->ip_src);
    inet_pton(AF_INET, "8.8.8.8", &ipHeader->ip_dst); // Using Google DNS (8.8.8.8)

    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = computeIpChecksum(ipHeader);

    // Build the UDP header
    struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    udpHeader->uh_sport = htons(rand() % 65535);
    udpHeader->uh_dport = htons(DNS_PORT);
    udpHeader->len = htons(sizeof(struct udphdr) + dnsQueryLength);
    udpHeader->check = 0;

    // Copy the DNS query to the packet, and compute the UDP checksum
    // DNS payload will be positioned after the UDP header, because of the layered structure of the packet. (Ethernet header | IP header | UDP header | DNS header + DNS query payload)
    // UDP checksum will be computed overall the UDP header and the DNS payload.
    memcpy(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr), dnsQuery, dnsQueryLength);
    udpHeader->check = computeUdpChecksum(ipHeader, udpHeader, packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr), dnsQueryLength);

    // Send the packet
    if (pcap_inject(handle, packet, packetSize) == -1) {
        pcap_perror(handle, "Error sending packet");
        free(packet);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("DNS query for %s sent successfully.\n", hostname);

    free(packet);
    pcap_close(handle);

    return EXIT_SUCCESS;
}

