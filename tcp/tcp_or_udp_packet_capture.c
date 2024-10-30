#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

unsigned int packetCount = 0;

void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	packetCount++;

	// Ethernet header (first 14 bytes)
	struct ether_header *ethernetHeader = (struct ether_header *)packet;

	// Only proceed if the packet is an IP packet (type 0x0800)
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
		printf("\n ----- [%05d] packet captured -----\n", packetCount);
		printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
		printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
		printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->ether_shost));
		printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->ether_dhost));

		// Check if the IP protocol is TCP or UDP
		if (ipHeader->ip_p == IPPROTO_TCP) {
			struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + \
			                                              (ipHeader->ip_hl * 4));
			printf("Protocol: TCP\n");
			printf("Source port: %d\n", ntohs(tcpHeader->th_sport));
			printf("Destination port: %d\n", ntohs(tcpHeader->th_dport));
		} else if (ipHeader->ip_p == IPPROTO_UDP) {
			struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + \
			                                              (ipHeader->ip_hl * 4));
			printf("Protocol: UDP\n");
			printf("Source port: %d\n", ntohs(udpHeader->uh_sport));
			printf("Destination port: %d\n", ntohs(udpHeader->uh_dport));
		} else {
			printf("Protocol: Other (%d)\n", ipHeader->ip_p);
		}
	}
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char* interface = argv[1];
    printf("Listening on %s...\n", interface);
    
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;                // Compiled filter expression
	char filterExpression[] = "tcp or udp"; // Capture both TCP and UDP packets
	bpf_u_int32 net;

	// Open the packet capture interface
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errorBuffer);
	if (handle == NULL) {
		fprintf(stderr, "Could not open the interface %s: %s\n", interface, errorBuffer);
		return 1;
	}

	// Compile and set the filter
	if (pcap_compile(handle, &fp, filterExpression, 0, net) == -1) {
		fprintf(stderr, "Could not parse filter %s: %s\n", filterExpression, pcap_geterr(handle));
		return 1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Could not install filter %s: %s\n", filterExpression, pcap_geterr(handle));
		return 1;
	}

	printf("Listening on %s...\n", interface);

	// Capture packets and process them with packet handler
	pcap_loop(handle, 0, packetHandler, NULL);

	// Close the handle
	pcap_close(handle);
	return 0;
}

