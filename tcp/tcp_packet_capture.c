#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

unsigned int packetCount = 0;

void packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	packetCount++;

	// Ethernet header (first 14 bytes)
	struct ether_header *ethernetHeader = (struct ether_header *)packet;

	// Only proceed if the packet is an IP packet (type 0x0800)
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		struct ip *ipHeader      = (struct ip *)(packet + sizeof(struct ether_header));
		struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + \
			                                              (ipHeader->ip_hl * 4));
			// ipHeader->ip_hl * 4 for the size of the IPv4 header

		printf("\n ----- [%05d] packet captured -----\n", packetCount);
		printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
		printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));
		printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->ether_shost));
		printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)ethernetHeader->ether_dhost));

		if (ipHeader->ip_p == IPPROTO_TCP) {
			printf("Protocol: TCP\n");
			printf("Source port: %d\n", ntohs(tcpHeader->th_sport));
			printf("Destination port: %d\n", ntohs(tcpHeader->th_dport));
		} else {
			printf("Protocol: %d\n", ipHeader->ip_p);
		}
	}
}

int main(void) {
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;			// Compiled filter expression
	char filterExpression[] = "tcp";	// The filter expression for only TCP packets
	bpf_u_int32 net;

	// Open the packet capture interface
	handle = pcap_open_live("enp3s0", BUFSIZ, 1, 1000, errorBuffer);
	if (handle == NULL) {
		fprintf(stderr, "Could not open the interface %s: %s\n", "enp0s3", errorBuffer);
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

	printf("Listening on %s...\n", "enp0s3");

	// Capture packets and process them with packet handler
	pcap_loop(handle, 0, packetHandler, NULL);

	// Close the handle
	pcap_close(handle);
	return 0;
}
