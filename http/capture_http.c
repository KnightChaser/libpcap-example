#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

unsigned int httpPacketCount = 0;

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ipHeader = (struct ip *)(packet + 14); // Assuming Ethernet header is 14 bytes
    if (ipHeader->ip_p != IPPROTO_TCP) 
        return; // Check if it’s TCP

    int ipHeaderLength = ipHeader->ip_hl * 4;
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeaderLength);
    int tcpHeaderLength = tcpHeader->th_off * 4;

    const u_char *payload = packet + 14 + ipHeaderLength + tcpHeaderLength;
    int payloadLength = header->caplen - (14 + ipHeaderLength + tcpHeaderLength);


    if (payloadLength > 0 && ((ntohs(tcpHeader->th_dport) == 80) || (ntohs(tcpHeader->th_dport) == 443))) {
        // Get connection information
        httpPacketCount++;
        printf("============ [%05d] ============\n", httpPacketCount);
        printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
        printf("Source Port: %d\n", ntohs(tcpHeader->th_sport));
        printf("Destination Port: %d\n", ntohs(tcpHeader->th_dport));
        
        char *payloadText = (char *)payload;
        char *hostPointer = strstr(payloadText, "Host: ");
        if (hostPointer) {
            char host[512];
            sscanf(hostPointer, "Host: %500s", host); 
            printf("Destination URL: %s\n", host);
        }

        // Print payload like 6e 65 63 74 69 6f 6e 3a 20 6b 65 65 70 2d 61 6c  | nection: keep-al
        for (unsigned int index = 0; index < payloadLength; index += 16) {
            // Hexadecimal part
            printf("\n");
            for (unsigned int i = 0; i < 16; i++)
                printf("%02x ", payload[index + i]);

            printf(" | ");

            for (unsigned int i = 0; i < 16; i++) {
                if (index + i < payloadLength) {
                    char byte = payload[index + i];
                    // Print only printable characters
                    if (byte > 31 && byte < 127)
                        printf("%c", byte);
                    else
                        printf(".");
                }
            }
        }

        printf("\n\n\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char* interface = argv[1];
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errBuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errBuf);
        return 2;
    }

    struct bpf_program fp;
    char filterExp[] = "tcp port 80"; // Change to capture HTTPS if desired
    if (pcap_compile(handle, &fp, filterExp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Could not parse filter %s: %s\n", filterExp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not install filter %s: %s\n", filterExp, pcap_geterr(handle));
        return 2;
    }

    pcap_loop(handle, 0, packetHandler, NULL);
    pcap_close(handle);
    return 0;
}

