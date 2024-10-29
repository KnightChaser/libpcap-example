#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string.h>

unsigned int packetCount = 0;

// DNS header structure
struct dnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};

// Function to parse and print the DNS query name
void parseDnsQueryName(const u_char *dnsData, int startOffset) {
    printf("Query Name: ");
    int i = startOffset;
    while (dnsData[i] != 0) {
        int labelLength = dnsData[i];
        i++;
        for (int j = 0; j < labelLength; j++) {
            printf("%c", dnsData[i + j]);
        }
        i += labelLength;
        if (dnsData[i] != 0) {
            printf(".");
        }
    }
    printf("\n");
}

void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packetCount++;

    struct ether_header *ethernetHeader = (struct ether_header *)packet;

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        if (ipHeader->ip_p == IPPROTO_UDP) {
            struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));

            // Check if the UDP packet is a DNS packet (port 53)
            if (ntohs(udpHeader->uh_dport) == 53 || ntohs(udpHeader->uh_sport) == 53) {
                printf("\n----- [%05d] DNS Packet Captured -----\n", packetCount);
                printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));

                // DNS data starts after UDP header
                const u_char *dnsData = packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4) + sizeof(struct udphdr);
                struct dnsHeader *dnsHeader = (struct dnsHeader *)dnsData;

                printf("Transaction ID: 0x%04x\n", ntohs(dnsHeader->id));

                // Determine if it's a request or a response
                if ((ntohs(dnsHeader->flags) & 0x8000) == 0) {
                    printf("Message Type: Query\n");
                } else {
                    printf("Message Type: Response\n");
                }

                printf("Questions: %d\n", ntohs(dnsHeader->qdCount));
                printf("Answers: %d\n", ntohs(dnsHeader->anCount));
                printf("Authority RRs: %d\n", ntohs(dnsHeader->nsCount));
                printf("Additional RRs: %d\n", ntohs(dnsHeader->arCount));

                // Print the query name for the first question (if any)
                if (ntohs(dnsHeader->qdCount) > 0) {
                    parseDnsQueryName(dnsData, sizeof(struct dnsHeader));
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *interface = argv[1];
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filterProgram;
    char filterExpression[] = "udp port 53"; // Filter for DNS (UDP on port 53)
    bpf_u_int32 net;

    // Open the packet capture interface
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open the interface %s: %s\n", interface, errorBuffer);
        return 1;
    }

    // Compile and set the filter
    if (pcap_compile(handle, &filterProgram, filterExpression, 0, net) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filterExpression, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &filterProgram) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filterExpression, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Listening on %s for DNS packets...\n", interface);

    // Capture packets and process them with packet handler
    pcap_loop(handle, 0, packetHandler, NULL);

    // Close the handle
    pcap_close(handle);
    return 0;
}

