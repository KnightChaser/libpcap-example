#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#ifndef U_CHAR
typedef unsigned char UChar;
#endif

void printPayload(const UChar *payload, int len) {
    int i;

    for (i = 0; i < len; i += 8) {
        printf("\n  ");
        for (int j = 0; j < 8; j++) {
            if (i + j < len) {
                printf("%02x ", payload[i + j]);
            } else {
                printf("   ");
            }
        }
        printf("| ");
        for (int j = 0; j < 8; j++) {
            if (i + j < len) {
                if (payload[i + j] >= 32 && payload[i + j] <= 126) {
                    printf("%c", payload[i + j]);
                } else {
                    printf(".");
                }
            }
        }
    }
    printf("\n");
}

void packetHandler(UChar *userData, const struct pcap_pkthdr *packetHeader, const UChar *packet) {
    struct ip *ipHeader;
    struct tcphdr *tcpHeader;
    u_int ipHeaderLength;
    u_int tcpHeaderLength;

    ipHeader = (struct ip *)(packet + 14);
    ipHeaderLength = ipHeader->ip_hl * 4;

    if (ipHeader->ip_p != IPPROTO_TCP) return;

    tcpHeader = (struct tcphdr *)(packet + 14 + ipHeaderLength);
    tcpHeaderLength = tcpHeader->th_off * 4;

    printf("TCP Packet Details:\n");
    printf("  Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("  Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
    printf("  Source Port: %d\n", ntohs(tcpHeader->th_sport));
    printf("  Destination Port: %d\n", ntohs(tcpHeader->th_dport));
    printf("  Sequence Number: %u\n", ntohl(tcpHeader->th_seq));
    printf("  Acknowledgment Number: %u\n", ntohl(tcpHeader->th_ack));
    printf("  Data Offset: %d\n", tcpHeader->th_off);

    printf("  Flags: 0x%02x\n", tcpHeader->th_flags);
    printf("    SYN: %s\n", (tcpHeader->th_flags & TH_SYN) ? "Set" : "Not Set");
    printf("    ACK: %s\n", (tcpHeader->th_flags & TH_ACK) ? "Set" : "Not Set");
    printf("    FIN: %s\n", (tcpHeader->th_flags & TH_FIN) ? "Set" : "Not Set");
    printf("    RST: %s\n", (tcpHeader->th_flags & TH_RST) ? "Set" : "Not Set");
    printf("    PSH: %s\n", (tcpHeader->th_flags & TH_PUSH) ? "Set" : "Not Set");
    printf("    URG: %s\n", (tcpHeader->th_flags & TH_URG) ? "Set" : "Not Set");

    printf("  Window Size: %d\n", ntohs(tcpHeader->th_win));
    printf("  Checksum: 0x%04x\n", ntohs(tcpHeader->th_sum));
    printf("  Urgent Pointer: %d\n", tcpHeader->th_urp);

    const UChar *payload = packet + 14 + ipHeaderLength + tcpHeaderLength;
    int payloadSize = packetHeader->len - (14 + ipHeaderLength + tcpHeaderLength);

    printf("  Payload Size: %d bytes\n", payloadSize);
    if (payloadSize > 0) {
        printf("  Payload (Hex Dump):");
        printPayload(payload, payloadSize);
    } else {
        printf("  No Payload Data\n");
    }

    printf("---------------------------------\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network device name>\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errBuf);
        return 2;
    }

    struct bpf_program filterProgram;
    if (pcap_compile(handle, &filterProgram, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter: %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filterProgram) == -1) {
        fprintf(stderr, "Could not install filter: %s\n", pcap_geterr(handle));
        return 2;
    }

    printf("Listening on device: %s\n", dev);

    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
    return 0;
}

