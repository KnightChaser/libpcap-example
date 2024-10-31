#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void packetHandler(unsigned char *userData, const struct pcap_pkthdr *packetHeader, const unsigned char *packet) {
    struct ip *ipHeader;
    struct icmphdr  *icmpHeader;
    unsigned int ipHeaderLength;

    // Position IP header after the Ethernet header (14 bytes)
    ipHeader = (struct ip *)(packet + 14);
    ipHeaderLength = ipHeader->ip_hl * 4;       // IP header length is in 4-byte words, IPv4 only.

    // CHeck if the protocol is ICMP
    if (ipHeader->ip_p != IPPROTO_ICMP)
        return;

    // Position ICMP header after the IP header
    icmpHeader = (struct icmphdr *)(packet + 14 + ipHeaderLength);

    printf("ICMP packet received\n");
    printf(" - Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
    printf(" - Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
    printf(" - ICMP Type: %d\n", icmpHeader->type);
    printf(" - ICMP Code: %d\n", icmpHeader->code);
    printf(" - ICMP Checksum: %d\n", icmpHeader->checksum);

    if (icmpHeader->type == ICMP_ECHO)
        printf(" -> ICMP Request(Ping)\n");
    else if (icmpHeader->type == ICMP_ECHOREPLY)
        printf(" -> ICMP Reply(Pong)\n");
    else if (icmpHeader->type == ICMP_DEST_UNREACH)
        printf(" -> Destination Unreachable\n");
    else if (icmpHeader->type == ICMP_TIME_EXCEEDED)
        printf(" -> Time Exceeded\n");
    else
        printf(" -> Other ICMP packet\n");

    printf("-------------------------------------------\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char *interface = argv[1];
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for the packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errorBuffer);
        return 2;
    }

    // Capture the ICMP packets only via BPF(Berkeley Packet Filter) expression
    struct bpf_program filterProgram;
    if (pcap_compile(handle, &filterProgram, "icmp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", "icmp", pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &filterProgram) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", "icmp", pcap_geterr(handle));
        return 2;
    }

    printf("Listening ICMP packets on %s...\n", interface);

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, NULL);

    // Close the handle
    pcap_close(handle);

    return 0;
}
