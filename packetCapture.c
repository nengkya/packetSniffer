int main() {

    /*
    typedef pcap_if pcap_if_t

	pcap_if * next
		if not NULL, a pointer to the next element in the list; NULL for the last element of the list.
	char * name
		a pointer to a string giving a name for the device to pass to pcap_open_live()
	char * description
		if not NULL, a pointer to a string giving a human-readable description of the device
	pcap_addr * addresses
		a pointer to the first element of a list of addresses for the interface
	u_int flags
		PCAP_IF_ interface flags. Currently the only possible flag is PCAP_IF_LOOPBACK,
		that is set if the interface is a loopback interface.

	struct pcap_addr * next
		if not NULL, a pointer to the next element in the list; NULL for the last element of the list
	struct sockaddr * addr
		a pointer to a struct sockaddr containing an address
	struct sockaddr * netmask
		if not NULL, a pointer to a struct sockaddr that contains the netmask corresponding to the address pointed to by addr.
	struct sockaddr * broadaddr
		if not NULL, a pointer to a struct sockaddr that contains the broadcast address corresponding to the address pointed to by addr;
		may be null if the interface doesn't support broadcasts
	struct sockaddr * dstaddr
		if not NULL, a pointer to a struct sockaddr that contains the destination address corresponding to the address pointed to by addr;
		may be null if the interface isn't a point- to-point interface









    */
    pcap_if_t * allDevices;

}
