#include <stdlib.h>
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
    */

    pcap_if_t * allDevices, * device;
    int i = 0;
    /*#define PCAP_ERRBUF_SIZE 256*/
    char errorBufferChar256[PCAP_ERRBUF_SIZE];
    /*int pcap_findalldevs(pcap_if_t ** alldevsp, char * errbuf); alldevsp is all devices pointer*/
    if (pcap_findalldevs(&allDevices, errorBufferChar256) == -1)
        fprintf(stderr, "%s\n",errorBufferChar256);
    
    char * DeviceIsPointerToChar = (char *)malloc(55 * sizeof(char));
    for (device = allDevices; device != NULL; device = device->next) {
		if (1 == i) {
	    	DeviceIsPointerToChar = device->name;
		}
		printf("%d. %s ", ++i, device->name);
		if (device->description)
	    	printf("%s", device->description);
		printf("\n");
    }

    device = allDevices;

    bpf_u_int32 *  netIsPointerToBPFunsignedInt32 = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
    bpf_u_int32 * maskIsPointerToBPFunsignedInt32 = (bpf_u_int32 *)malloc(sizeof(bpf_u_int32));
    pcap_lookupnet(device->name, netIsPointerToBPFunsignedInt32, maskIsPointerToBPFunsignedInt32, errorBufferChar256);
    fprintf(stderr, "%s\n", device->name);

    /*:noh = no highlight after search in nvim*/
    /*opening the device for sniffing
    typedef struct pcap {
		int fd;
		int snapshot;
		int linktype;
		int tzoff;					//timezone offset
		int offset;					//offset for proper alignment
		struct pcap_sf sf;
		struct pcap_md md; //metadata
		int bufsize;				//read buffer
		u_char * buffer;
		u_char * bp;				//buff pointer
		int cc;						//current capture
		u_char * pkt;				//place holder for packet pcap_next()
		//placeholder for filter code if bpf (barkley packet filter) not in kernel
		struct bpf_program;
		struct bpf_insn * bf_insns;	//pointer to an array of bp finstructions
		u_int  bf_len;				//number of instructions in the array
	} pcap_t;
 
	struct pcap_sf {
	    size_t hdrsize; //header size
	    swapped_type_t lengths_swapped;
	    tstamp_scale_type_t scale_type;
	};

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
	these constants specify the source and characteristics of the timestamp applied to captured packets.
	the available timestamp types include :
	PCAP_TSTAMP_HOST				 : Timestamp provided by the host machine
	PCAP_TSTAMP_HOST_LOWPREC		 : Low-precision timestamp from the host
	PCAP_TSTAMP_HOST_HIPREC			 : High-precision timestamp from the host
	PCAP_TSTAMP_HOST_HIPREC_UNSYNCED : High-precision, unsynchronized timestamp from the host
	PCAP_TSTAMP_ADAPTER				 : Timestamp provided by the network adapter
	PCAP_TSTAMP_ADAPTER_UNSYNCED	 : timestamp from the network adapter, not synchronized with the system clock

	struct pcap_md {
		struct pcap_stat stat;
		int use_bpf;		 using kernel filter
		u_long	TotPkts;	 can't oflow for 79 hrs on ether
		u_long	TotAccepted; count accepted by filter
		u_long	TotDrops;	 count of dropped packets
		long	TotMissed;	 missed by i/f during this run
		long	OrigMissed;	 missed by i/f before this run
		char	*device;	 device name
		int	timeout;		 timeout for buffering
		int	must_clear;		 stuff we must clear when we close
		struct pcap *next;	 list of open pcaps that need stuff cleared on close
		#ifdef linux
			int	sock_packet; 	 using Linux 2.0 compatible interface
			int	cooked;		 	 using SOCK_DGRAM rather than SOCK_RAW
			int	ifindex;	 	 interface index of device we're bound to
			int	lo_ifindex;	 	 interface index of the loopback device
			u_int packets_read;  count of packets read with recvfrom()
			bpf_u_int32 oldmode; mode to restore when turning monitor mode off
			u_int tp_version;	 version of tpacket_hdr for mmaped ring
			u_int tp_hdrlen;	 hdrlen of tpacket_hdr for mmaped ring
		#endif linux
		
		#ifdef HAVE_DAG_API
			#ifdef HAVE_DAG_STREAMS_API
				u_char * dag_mem_bottom; DAG card current memory bottom pointer
				u_char * dag_mem_top; DAG card current memory top pointer
			#else HAVE_DAG_STREAMS_API
				void   * dag_mem_base;	DAG card memory base address
				u_int  	 dag_mem_bottom;	DAG card current memory bottom offset
				u_int    dag_mem_top;	DAG card current memory top offset
			#endif HAVE_DAG_STREAMS_API
			int	dag_fcs_bits;	Number of checksum bits from link layer
			int	dag_offset_flags; Flags to pass to dag_offset().
			int	dag_stream;	DAG stream number
			int	dag_timeout;	timeout specified to pcap_open_live.Same as in linux above, introducegenerally ?
		#endif HAVE_DAG_API

		#ifdef HAVE_ZEROCOPY_BPF
			Zero-copy read buffer -- for zero-copy BPF.  'buffer' above will
			alternative between these two actual mmap'd buffers as required.
			As there is a header on the front size of the mmap'd buffer, only
			some of the buffer is exposed to libpcap as a whole via bufsize;
			zbufsize is the true size.  zbuffer tracks the current zbuf
			assocated with buffer so that it can be used to decide which the
			next buffer to read will be.

			Zero-copy is a technique that allows data to be transferred between parts of a system
			without copying the data.
			This can improve system performance by reducing CPU usage and memory bandwidth. 
			How it works
				Data remains in its original location
				Pointers or references to the data are passed around 
			Benefits 
				Performance
				Zero-copy can improve performance for applications that require high data throughput,
				such as network communication, file I/O, and multimedia processing 
			Cost
				Zero-copy can reduce the expense and risk of errors that can occur when data is moved or changed 
			Integration
				Zero-copy can make it easier to access data from multiple databases at the same time 
			Examples
				Salesforce
				Zero-copy allows organizations to connect and use all of their data within the Einstein 1 Platform
				without needing to move or copy data between platforms 
			Fast Data Distribution Service
				Zero-copy communication can be enabled by defining a plain and bounded type
				in an Interface Definition Language file

		    u_char * zbuf1, * zbuf2, * zbuffer; zero-copy buffer
		    u_int zbufsize;
		    u_int zerocopy;
		    u_int interrupted;
		    struct timespec firstsel;
			If there's currently a buffer being actively processed, then it is
			referenced here; 'buffer' is also pointed at it, but offset by the
			size of the header.
		    struct bpf_zbuf_header *bzh;
		#endif HAVE_ZEROCOPY_BPF
		
		#ifdef HAVE_REMOTE
			There is really a mess with previous variables, and it seems to me that they are not used
			(they are used in pcap_pf.c only). I think we have to start using them.
			The meaning is the following:
		
			- TotPkts: the amount of packets received by the bpf filter, *before* applying the filter
			- TotAccepted: the amount of packets that satisfies the filter
			- TotDrops: the amount of packet that were dropped into the kernel buffer because of lack of space
			- TotMissed: the amount of packets that were dropped by the physical interface; it is basically
				the value of the hardware counter into the card. This number is never put to zero, so this number
				takes into account the *total* number of interface drops starting from the interface power-on.
			- OrigMissed: the amount of packets that were dropped by the interface *when the capture begins*.
				This value is used to detect the number of packets dropped by the interface *during the present
				capture*, so that (ps_ifdrops= TotMissed - OrigMissed).
			unsigned int TotNetDrops;       //!< keeps the number of packets that have been dropped by the network

			\brief It keeps the number of packets that have been received by the application.
			Packets dropped by the kernel buffer are not counted in this variable. The variable is always
			equal to (TotAccepted - TotDrops), exept for the case of remote capture, in which we have also
			packets in fligh, i.e. that have been transmitted by the remote host, but that have not been
			received (yet) from the client. In this case, (TotAccepted - TotDrops - TotNetDrops) gives a
			wrong result, since this number does not corresponds always to the number of packet received by
			the application. For this reason, in the remote capture we need another variable that takes
			into account of the number of packets actually received by the application.
			unsigned int TotCapt;
		#endif HAVE_REMOTE
		
	};
	
 	struct bpf_program {
	    struct bpf_insn * bf_insns; //pointer to the compiled BPF bytecode instructions
	    u_int bf_len;               //number of instructions in the program
	};

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
	    .jt   =  0,	   //no jump
	    .jf	  =  0,	   //no jump
	    .k	  = 12	   //offset where ether type field is located in ethernet frame
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
		{BPF_RET | BPF_K, 0, 0, 0 }					  //otherwise, drop
	};
	*/
    struct bpf_program * fcode = (struct bpf_program *)malloc(sizeof(struct bpf_program));

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
    LINKTYPE_ETHERNET	1			DLT_EN10MB			IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb,
									and up);
									the 10MB in the DLT_ name is historical 
    */
    if (pcap_datalink(handle) != DLT_EN10MB)
	fprintf(stderr,
	    "Device %s doesnt provide ethernet headers - not supported\n", DeviceIsPointerToChar);

    /*int pcap_compile(pcap_t * p, struct bpf_program * fp, char * str, int optimize, bpf_u_int32 mask);*/
    //pcap_compile(handle, fcode);

    /*int pcap_setfilter(pcap_t * p, struct bpf_program * fp);*/
    pcap_setfilter(handle, fcode);

}
