#include <stdlib.h>
#include "pcap.h"

int main() {

    /*
    typedef pcap_if pcap_if_t {
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
    }

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
    }

    struct sockaddr {
	sa_family_t     sa_family; //socket addres
	char            sa_data[];
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

    typedef pcap_if pcap_if_t {
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

    */

    pcap_if_t * allDevices, * device;
    int i = 0;
    /*#define PCAP_ERRBUF_SIZE 256*/
    char errorBufferChar256[PCAP_ERRBUF_SIZE];
    /*
    int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf); alldevsp is all devices pointer
    */
    if (pcap_findalldevs(&allDevices, errorBufferChar256) == -1)
        fprintf(stderr, "%s\n",errorBufferChar256);
    
    char * DeviceIsPointerToChar = (char *)malloc(55 * sizeof(char));
    for (device = allDevices; device != NULL; device = device->next) {
	printf("%d. %s ", ++i, device->name);
	if (1 == i) {
	    DeviceIsPointerToChar = device->name;
	}
	if (device->description)
	    printf("%s", device->description);
	printf("\n");
    }

    pcap_findalldevs(&allDevices, errorBufferChar256);
    device = allDevices;

    bpf_u_int32 *  netIsPointerToBPFunsignedInt32 = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
    bpf_u_int32 * maskIsPointerToBPFunsignedInt32 = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
    pcap_lookupnet(device->name, netIsPointerToBPFunsignedInt32,
	    maskIsPointerToBPFunsignedInt32, errorBufferChar256);

    /*:noh = no highlight after search in nvim*/
    /*opening the device for sniffing
    typedef struct pcap pcap_t
    struct pcap {
	int fd;
	int snapshot;
	int linktype;
	int tzoff;      		//timezone offset
	int offset;     		//offset for proper alignment
	struct pcap_sf sf;
	struct pcap_md md;
	int bufsize;			//read buffer
	u_char * buffer;
	u_char * bp;			//buff pointer
	int cc;				//current capture
	u_char * pkt;			//place holder for packet pcap_next()
	//placeholder for filter code if bpf (barkley packet filter) not in kernel
	struct bpf_program {
	struct bpf_insn * bf_insns; 	//pointer to an array of bp finstructions
	u_int  bf_len;              	//number of instructions in the array
	};
	struct pcap_sf {
	    size_t hdrsize;
	    swapped_type_t lengths_swapped;
	    tstamp_scale_type_t scale_type;
	};
	struct bpf_program {
	    struct bpf_insn * bf_insns; //pointer to the compiled BPF bytecode instructions
	    u_int bf_len;               //number of instructions in the program
	};
	struct bpf_insn {
	    typedef enum {
		NOT_SWAPPED,
		SWAPPED,
		MAYBE_SWAPPED
	} swapped_type_t;
	typedef enum {
	    TSTAMP_SCALE_SECONDS
	    TSTAMP_SCALE_MILLISECONDS
	    TSTAMP_SCALE_MICROSECONDS
	    TSTAMP_SCALE_NANOSECONDS
	    TSTAMP_SCALE_UNKNOWN (for an undefined or error case)
	} tstamp_scale_type_t
	timestamp types are integer constants rather than typedef tstamp_scale_type_t
	these constants specify the source and characteristics of
	the timestamp applied to captured packets.
	the available timestamp types include :
	PCAP_TSTAMP_HOST: Timestamp provided by the host machine
	PCAP_TSTAMP_HOST_LOWPREC: Low-precision timestamp from the host
	PCAP_TSTAMP_HOST_HIPREC: High-precision timestamp from the host
	PCAP_TSTAMP_HOST_HIPREC_UNSYNCED: High-precision, unsynchronized timestamp from the host
	PCAP_TSTAMP_ADAPTER: Timestamp provided by the network adapter
	PCAP_TSTAMP_ADAPTER_UNSYNCED: timestamp from the network adapter,
				      not synchronized with the system clock
	struct bpf_insn {
	    u_short code;  //operation code (opcode)
	    u_char  jt;    //jump offset if true
	    u_char  jf;    //jump offset if false
	    u_int   k;     //generic field for constants, offsets, or addresses
	    u_short code;  //operation code (opcode)
	    u_char  jt;    //jump offset if true
	    u_char  jf;    //jump offset if false
	    u_int   k;     //generic field for constants, offsets, or addresses
	};
	struct bpf_insn insn = {
	    .code = BPF_LD | BPF_H | BPF_ABS,//load 16-bit halfword at absolute offset
	    .jt   =  0,			     //no jump
	    .jf	  =  0,			     //no jump
	    .k	  = 12		   	   //offset where ether type field is located in ethernet frame
	};
	bpf opcode	meaning
	BPF_LD		load data into accumulator
	BPF_LDX		load data into index register
	BPF_ST		store accumulator value
	BPF_STX		store index register value
	BPF_ALU		perform arithmetic/logic operations
	BPF_JMP		perform jump (conditional or unconditional)
	BPF_RET		return a packet decision (accept/drop)
	bpf example : filter tcp packets
	a compiled bpf program for filtering tcp packets might consist of
	multiple bpf_insn instructions, structured like :
	struct bpf_insn bpf_program[] = {
	{BPF_LD  | BPF_H   | BPF_ABS, 0, 0,     12 }, //load ether type
	{BPF_JMP | BPF_JEQ | BPF_K,   0, 1, 0x0800 }, //if ipv4, continue
	{BPF_RET | BPF_K, 0, 0, 0 }		      //otherwise, drop
	};
	*/
    struct bpf_program * fcode;

    /*
    snapshot length of data capture = BUF_SIZ
    promisc refers to promiscuous mode = 1 (enable) or 0 (disable)
    which is a network interface setting that allows a device
    to capture all network traffic passing by,
    regardless of whether the packets are addressed to it specifically
    timeoffset_in_milliseconds = 1000
    error buffer
    pcap_t * pcap_open_live(char * device, int snaplen, int promisc, int to_ms, char * ebuf);
    #define BUFSIZ 8192 in /usr/include/stdio.
    handle translated into manage
    */
    pcap_t * handle;
    handle = pcap_open_live(DeviceIsPointerToChar, BUFSIZ, 1, 1000, errorBufferChar256);
    if (handle == NULL)
	fprintf(stderr, "%s %s\n", DeviceIsPointerToChar, errorBufferChar256);

    /*
    LINKTYPE_name 	LINKTYPE_value 	corresponding DLT_  name description
    LINKTYPE_ETHERNET 	1 		DLT_EN10MB	    IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb,
							    and up);
							    the 10MB in the DLT_ name is historical 
    */
    if (pcap_datalink(handle) != DLT_EN10MB)
	fprintf(stderr,
	    "Device %s doesnt provide ethernet headers - not supported\n", DeviceIsPointerToChar);

    /*int pcap_compile(pcap_t * p, struct bpf_program * fp,
	char * str, int optimize, bpf_u_int32 mask);*/
    //pcap_compile(handle, fcode);

    /*int pcap_setfilter(pcap_t * p, struct bpf_program * fp);*/
    pcap_setfilter(handle, fcode);


}
