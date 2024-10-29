#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int packetCount = 0;

void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	packetCount++;
	printf("[%05u] Packet captured! length: %d\n", packetCount, header->len);
}

int main(void) {
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	// Open live capture on the network interface
	handle = pcap_open_live("enp3s0", BUFSIZ, 1, 1000, errorBuffer);
		// enp3s0: network interface name
		// BUFSIZ: maximum number of bytes to capture
		// 1: promiscuous mode
		// 1000: read timeout in milliseconds
		// errorBuffer: buffer to store error message
	if (handle == NULL) {
		fprintf(stderr, "Could not open device: %s\n", errorBuffer);
		return 2;
	}

	// Start capturing packets
	pcap_loop(handle, 0, packetHandler, NULL);
	        // handle: pcap_t object
		// 0: number of packets to capture before returning
		// packetHandler: callback function
		// NULL: arguments to callback function
	
	pcap_close(handle);
	return 0;
}
