#include "stdlib.h"
#include "pcap.h"


int main() {

	/*
    typedef struct pcap_if {
	pcap_if * next
	    if not NULL, a pointer to the next element in the list;
	    NULL for the last element of the list.
	char * name
	    a pointer to a string giving a name for the device to pass to pcap_open_live()
	char * description
	    if not NULL, a pointer to a string giving a human-readable description of the device
	pcap_addr * addresses
	    a pointer to the first element of a list of addresses for the interface
	u_int flags
	    PCAP_IF_ interface flags. Currently the only possible flag is PCAP_IF_LOOPBACK,
	    that is set if the interface is a loopback interface.
    } pcap_if_t;

    struct pcap_addr {
		struct pcap_addr * next
			if not NULL, a pointer to the next element in the list;
			NULL for the last element of the list
		struct sockaddr * addr
			a pointer to a struct sockaddr containing an address
		struct sockaddr * netmask
			if not NULL, a pointer to a struct sockaddr
			that contains the netmask corresponding to the address pointed to by addr.
		struct sockaddr * broadaddr
			if not NULL, a pointer to a struct sockaddr
			that contains the broadcast address corresponding to the address pointed to by addr;
			may be null if the interface doesn't support broadcasts
		struct sockaddr * dstaddr
			if not NULL, a pointer to a struct sockaddr
			that contains the destination address corresponding to the address pointed to by addr;
			may be null if the interface isn't a point- to-point interface
    };

    struct sockaddr {
		sa_family_t	sa_family; //socket addres
		char		sa_data[];
    };
    sa_family is socket address spesific family structure.
    Address Format :
    AF_LOCAL
    this designates the address format that goes with the local namespace.
    AF_UNIX
    this is a synonym for AF_LOCAL. Although AF_LOCAL is mandated by POSIX.1g,
    AF_UNIX is portable to more systems.
    AF_UNIX was the traditional name stemming from BSD, so even most POSIX systems support it.
    it is also the name of choice in the Unix98 specification.
    The same is true for PF_UNIX vs PF_LOCAL. PF is Protocol Format.
    AF_FILE
    this is another synonym for AF_LOCAL, for compatibility.
    PF_FILE is likewise a synonym for PF_LOCAL.
    AF_INET
    this designates the address format that goes with the Internet namespace.
    PF_INET is the name of that namespace.
    AF_INET6
    this is similar to AF_INET, but refers to the IPv6 protocol.
    PF_INET6 is the name of the corresponding namespace.
    AF_UNSPEC
    this designates no particular address format. It is used only in rare cases,
    such as to clear out the default destination address of a “connected” datagram socket.
    
	why cant use pcap_if_t ** allDevices;
	warning: assignment to ‘pcap_if_t *’ {aka ‘struct pcap_if *’} from incompatible pointer type ‘pcap_if_t **’
	{aka ‘struct pcap_if **’} [-Wincompatible-pointer-types]
	for (device = allDevices; device != 0; device = device.next)
	*/
	pcap_if_t * allDevices = (pcap_if_t *)malloc(sizeof(pcap_if_t)), * device;

	char errorBufferChar256[PCAP_ERRBUF_SIZE], * deviceNamePointer;

	int deviceNumber = 0;

	/*int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf); all devices pointer*/
	if (pcap_findalldevs(&allDevices, errorBufferChar256) == -1)
		fprintf(stderr, "%s\n", errorBufferChar256);

	for (device = allDevices; device != NULL; device = device->next) {

		if (1 == deviceNumber) deviceNamePointer = device->name;
    
		printf("%d. %s   ", ++deviceNumber, device->name);

		if (device->description) printf("%s", device->description);

		printf("\n");

	}

	/*
	pcap_lookup_net - find the IPv4 network number and netmask for a device
	int pcap_looup_net(de);
	*/





}






