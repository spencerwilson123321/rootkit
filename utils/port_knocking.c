#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

u_int16_t get_packet_type(const unsigned char* packet) {
    struct ether_header *eptr;  /* net/ethernet.h */
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    u_int16_t type = ntohs(eptr->ether_type);
    /* check to see if we have an ip packet */
    if (type == ETHERTYPE_IP) {
        fprintf(stdout,"(IP)\n");
    } else  if (type == ETHERTYPE_IPV6) {
        fprintf(stdout,"(IPV6)\n");
    } else {
        fprintf(stdout,"(?)\n");
    }
    return type;
}

/* 
    This program takes a device name as input,
    and sniffs packets using the libpcap library.
*/
int main(int argc, char** argv) {
    // DATA
    char errbuff[1024];
    char *dev;
    char *filter;

    // User passes NIC device name as argument.
    dev = argv[1];
    filter = argv[2];

    // Get network IP and MASK.
    bpf_u_int32 mask;
    bpf_u_int32 ip;
    if (pcap_lookupnet(dev, &ip, &mask, errbuff) == -1) {
        fprintf(stderr, "Can't get netmask for device: %s", dev);
        ip = 0;
        mask = 0;
    }
    
    // Open device for sniffing.
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuff);
    if (handle == NULL) {
        fprintf(stderr, "Device not found: %s", dev);
        exit(EXIT_FAILURE);
    };

    // Compile filter.
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 0, ip) == -1) {
        fprintf(stderr, "Filter compilation failed.");
        exit(EXIT_FAILURE);
    }

    // Apply the compiled filter.
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not set filter %s: %s\n", filter, pcap_geterr(handle));
	    return(EXIT_FAILURE);
    }

    /* 
        Now we perform the actual sniffing of packets.
    */
    struct pcap_pkthdr header;
    const unsigned char *packet = pcap_next(handle, &header);
    get_packet_type(packet);
    pcap_close(handle);
    return 0;
}

