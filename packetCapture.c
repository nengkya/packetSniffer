#include "pcap.h"


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

    struct sockaddr {
	ushort  sa_family;   //sa = socket address
	char    sa_data[14];
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
    */
    pcap_if_t * allDevices, * device;
    int i = 0;

    /*#define PCAP_ERRBUF_SIZE 256*/
    char errorBuffer[PCAP_ERRBUF_SIZE];

    /*
    int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf);
    alldevsp is all devices pointer
    */
    if (pcap_findalldevs(&allDevices, errorBuffer) == -1)
	fprintf(stderr, "%s\n",errorBuffer);
<<<<<<< HEAD
=======

    for (device = allDevices; device != NULL; device = device->next) {
	printf("%d. %s ", ++i, device->name);
	if (device->description)
	    printf("%s", device->description);
	printf("\n");
    }

    /*
    opening the device for sniffing

    typedef struct pcap pcap_t

    struct pcap {
	int fd;
	int snapshot;
	int linktype;
	int tzoff;      //timezone offset
	int offset;     //offset for proper alignment

	struct pcap_sf sf;
	struct pcap_md md;

	//read buffer.
	int bufsize;
	u_char * buffer;
	u_char * bp;	//buff pointer
	int cc;		//current capture

	//place holder for pcap_next()
	u_char * pkt;	//packet

	//placeholder for filter code if bpf not in kernel
	//barkley packet filter
	struct bpf_program {
	    struct bpf_insn * bf_insns; //pointer to an array of BPF instructions
	    u_int bf_len;               //number of instructions in the array
	};
	
	struct bpf_insn {
	    u_short code;  //operation code (opcode)
	    u_char  jt;    //jump offset if true
	    u_char  jf;    //jump offset if false
	    u_int   k;     //generic field for constants, offsets, or addresses
	};

	struct bpf_insn insn = {
	    .code = BPF_LD | BPF_H | BPF_ABS,  // Load 16-bit halfword at absolute offset
	    .jt = 0,  // No jump
	    .jf = 0,  // No jump
	    .k = 12   // Offset where EtherType field is located in Ethernet frame
	};
>>>>>>> 0fe2e5b2235018d15c79e26d83b9d1fb98bb5869

    for (device = allDevices; device != NULL; device = device->next) {
	printf("%d. %s ", ++i, device->name);
	if (device->description)
	    printf("%s", device->description);
	printf("\n");
    }

<<<<<<< HEAD
    /*
    opening the device for sniffing

    typedef struct pcap pcap_t

    struct pcap {
	int fd;
	int snapshot;
	int linktype;
	int tzoff;      //timezone offset
	int offset;     //offset for proper alignment

	struct pcap_sf sf;
	struct pcap_md md;

	//read buffer.
	int bufsize;
	u_char * buffer;
	u_char * bp;	//buff pointer
	int cc;		//current capture

	//place holder for pcap_next()
	u_char * pkt;	//packet

	//placeholder for filter code if bpf not in kernel
	//barkley packet filter
	struct bpf_program {
	    struct bpf_insn * bf_insns; //pointer to an array of BPF instructions
	    u_int bf_len;               //number of instructions in the array
	};
	
	struct bpf_insn {
	    u_short code;  //operation code (opcode)
	    u_char  jt;    //jump offset if true
	    u_char  jf;    //jump offset if false
	    u_int   k;     //generic field for constants, offsets, or addresses
	};

	struct bpf_insn insn = {
	    .code = BPF_LD | BPF_H | BPF_ABS,  // Load 16-bit halfword at absolute offset
	    .jt = 0,  // No jump
	    .jf = 0,  // No jump
	    .k = 12   // Offset where EtherType field is located in Ethernet frame
	};

	common bpf opcodes
	opcode	meaning
	BPF_LD	Load data into accumulator
	BPF_LDX	Load data into index register
	BPF_ST	Store accumulator value
	BPF_STX	Store index register value
	BPF_ALU	Perform arithmetic/logic operations
	BPF_JMP	Perform jump (conditional or unconditional)
	BPF_RET	Return a packet decision (accept/drop)

	BPF Example: Filter TCP Packets

	A compiled BPF program for filtering TCP packets might consist of
	multiple bpf_insn instructions, structured like:

	struct bpf_insn bpf_program[] = {
	    { BPF_LD  | BPF_H | BPF_ABS, 0, 0, 12 },  	//load ether type
	    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0800 },//if ipv4, continue
	    { BPF_RET | BPF_K, 0, 0, 0 } 		//otherwise, drop
	};

	struct bpf_program fcode;

	char errbuf[PCAP_ERRBUF_SIZE];
    };

=======


	struct bpf_program fcode;

	char errbuf[PCAP_ERRBUF_SIZE];
    };

>>>>>>> 0fe2e5b2235018d15c79e26d83b9d1fb98bb5869
    pcap_t * pcap_open_live();

    */

}
