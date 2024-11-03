#include <netinet/in.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main(void) {
    pcap_if_t *allInterfaces;
    pcap_if_t *currentInterface;
    char errorBuffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allInterfaces, errorBuffer) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errorBuffer);
        return 1;
    }

    if (!allInterfaces) {
        fprintf(stderr, "No interfaces found! Exiting.\n");
        return 1;
    }

    for (currentInterface = allInterfaces; currentInterface; currentInterface = currentInterface->next) {
        printf("Interface: %s\n", currentInterface->name);
        printf("Description: %s\n", currentInterface->description ? currentInterface->description : "No description available");
        printf("Loopback: %s\n", (currentInterface->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

        // Iterate through the addresses of the interface
        // Probably, multiple addresses can be assigned to an interface
        pcap_addr_t *currentAddress;
        for (currentAddress = currentInterface->addresses; currentAddress; currentAddress = currentAddress->next) {
            if (currentAddress->addr && currentAddress->addr->sa_family == AF_INET) {
                // IPv4
                printf("Address Family: AF_INET(IPv4)\n");
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)currentAddress->addr;
                printf(" Address: %s\n", inet_ntoa(ipv4->sin_addr));

                if (currentAddress->netmask) {
                    struct sockaddr_in *netmask = (struct sockaddr_in *) currentAddress->netmask;
                    printf(" Netmask: %s\n", inet_ntoa(netmask->sin_addr));
                }

                if (currentAddress->broadaddr) {
                    struct sockaddr_in *broadcast = (struct sockaddr_in *) currentAddress->broadaddr;
                    printf(" Broadcast Address: %s\n", inet_ntoa(broadcast->sin_addr));
                }
              
                if (currentAddress->dstaddr) {
                    struct sockaddr_in *destinationAddress = (struct sockaddr_in *) currentAddress->dstaddr;
                    printf(" Destination Address: %s\n", inet_ntoa(destinationAddress->sin_addr));
                }                
            } else if (currentAddress->addr && currentAddress->addr->sa_family == AF_INET6) {
                // IPv6
                printf("Address Family: AF_INET6(IPv6)\n");

                char addressBuffer[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) currentAddress->addr;
                inet_ntop(AF_INET6, &ipv6->sin6_addr, addressBuffer, sizeof(addressBuffer));
                printf(" Address: %s\n", addressBuffer);
            }
        }
        printf("\n");
    }

    pcap_freealldevs(allInterfaces);  // Free the allocated memory for interfaces

    return 0;
}

