#include <stdio.h>
#include <pcap/pcap.h>
#include "stdlib.h" /*exit();*/

int main() {

	/*
	struct pcap_t {
		int fd; 	  file descriptor
		int snapshot;
		int linktype;
		int tzoff;    timezone offset
		int offset;   offset for proper alignment

		struct pcap_sf sf; short frame chatGPT
		struct pcap_md md; metadaata

		//read buffer
		int bufsize;
		u_char * buffer;
		u_char * bp; buffer pointer
		int cc; 	 count of capture

		//place holder for pcap_next()
		u_char * pkt; packet

		//placeholder for filter code if bpf not in kernel.
		struct bpf_program fcode; barkley packet filter
		char errbuf[PCAP_ERRBUF_SIZE];
	};

	struct pcap_sf {
		size_t hdrsize; unsigned int header size
		swapped_type_t lengths_swapped;
		tstamp_scale_type_t scale_type;
	};

	struct pcap_md {
			struct pcap_stat stat;
			int use_bpf;		  using kernel filter
			u_long TotPkts;		  can't oflow for 79 hrs on ether
			u_long TotAccepted;	  count accepted by filter
			u_long TotDrops;	  count of dropped packets
			long   TotMissed;	  missed by i/f during this run
			long   OrigMissed;	  missed by i/f before this run
			char   * device;	  device name
			int	timeout;		  timeout for buffering
			int	must_clear;		  stuff we must clear when we close
			struct pcap * next;	  list of open pcaps that need stuff cleared on close
		#ifdef linux
			int	sock_packet;	  using Linux 2.0 compatible interface
			int	cooked;			  using SOCK_DGRAM rather than SOCK_RAW
			int	ifindex;		  interface index of device we're bound to
			int	lo_ifindex;		  interface index of the loopback device
			u_int packets_read;	  count of packets read with recvfrom()
			bpf_u_int32 oldmode;  mode to restore when turning monitor mode off
			u_int tp_version;	  version of transport packet header for mmaped ring
			u_int tp_hdrlen;	  header length of transport packet header for mmaped ring
		#endif linux

		#ifdef HAVE_DAG_API Data Acquisition and Generation
			#ifdef HAVE_DAG_STREAMS_API
				u_char * dag_mem_bottom; DAG card current memory bottom pointer
				u_char * dag_mem_top;	 DAG card current memory top pointer
			#else HAVE_DAG_STREAMS_API
				void   * dag_mem_base;	 DAG card memory base address
				u_int    dag_mem_bottom; DAG card current memory bottom offset
				u_int	 dag_mem_top;	 DAG card current memory top offset
			#endif HAVE_DAG_STREAMS_API
				int	dag_fcs_bits;		 number of checksum bits from link layer
				int	dag_offset_flags;	 flags to pass to dag_offset()
				int	dag_stream;			 DAG stream number
				int	dag_timeout;		 timeout specified to pcap_open_live. same as in linux above, introduce generally ?
		#endif HAVE_DAG_API

		#ifdef HAVE_ZEROCOPY_BPF
		zero-copy read buffer -- for zero-copy BPF. 'buffer' above will alternative between these two actual mmap'd buffers as required.
		as there is a header on the front size of the mmap'd buffer, only some of the buffer is exposed to libpcap as a whole via bufsize;
		zbufsize is the true size.
		zbuffer tracks the current zbuf assocated with buffer so that it can be used to decide which the next buffer to read will be.
			u_char *zbuf1, *zbuf2, *zbuffer;
			u_int zbufsize;
			u_int zerocopy;
			u_int interrupted;
			struct timespec firstsel;

			//if there's currently a buffer being actively processed, then it is referenced here;
			//'buffer' is also pointed at it, but offset by the size of the header.
			struct bpf_zbuf_header * bzh; zero-copy buffer
		#endif HAVE_ZEROCOPY_BPF



		#ifdef HAVE_REMOTE
			there is really a mess with previous variables, and it seems to me that they are not used
			(they are used in pcap_pf.c only). I think we have to start using them.
			The meaning is the following:

			- TotPkts	  : the amount of packets received by the bpf filter, *before* applying the filter
			- TotAccepted : the amount of packets that satisfies the filter
			- TotDrops	  : the amount of packet that were dropped into the kernel buffer because of lack of space
			- TotMissed	  : the amount of packets that were dropped by the physical interface;
							it is basically the value of the hardware counter into the card.
							this number is never put to zero, so this number takes into account the *total* number of
							interface drops starting from the interface power-on.
			- OrigMissed  : the amount of packets that were dropped by the interface *when the capture begins*.
							this value is used to detect the number of packets dropped by the interface
							*during the present capture*, so that (ps_ifdrops = TotMissed - OrigMissed).

			unsigned int TotNetDrops; keeps the number of packets that have been dropped by the network

			\brief It keeps the number of packets that have been received by the application.
			packets dropped by the kernel buffer are not counted in this variable.
			the variable is always equal to (TotAccepted - TotDrops),
			except for the case of remote capture, in which we have also packets in fligh, i.e. that have been transmitted by the remote host,
			but that have not been received (yet) from the client.
			in this case, (TotAccepted - TotDrops - TotNetDrops) gives a wrong result,
			since this number does not corresponds always to the number of packet received by the application.
			for this reason, in the remote capture we need another variable that takes into
			account of the number of packets actually received by the application.
			unsigned int TotCapt;
		#endif HAVE_REMOTE

	};
	
	en → ethernet interface
	p0 → PCI bus number (bus 0)
	s3 → slot number 3

	snaplen is "snapshot length".
	it specifies the maximum number of bytes to capture from each packet.
	larger snaplen captures more of the packet but may use more memory and processing power.
	smaller snaplen captures only part of the packet, which can be useful for performance optimization
	if you only need headers (e.g., capturing just ethernet/IP/TCP headers without full payloads).
	if snaplen is too small, some packet data may be truncated.
	
	promisc is "promiscuous mode" (select all).
	1 enables  promiscuous mode, meaning the network interface captures all packets, including those not addressed to it.
	0 disables promiscuous mode, meaning the interface captures only packets addressed to it or broadcast packets.
	promiscuous mode is useful for network analysis and security monitoring.
	pcap_t * pcap_open_live(const char * device, int snaplen, int promisc, int timeout_ms, char * errbuf);
	*/
	char * device = "enp0s3";
	char errorBuffer[PCAP_ERRBUF_SIZE];
	pcap_t * capturedDevice = pcap_open_live(device, BUFSIZ, 0, -1, errorBuffer);

	if (NULL == capturedDevice) {
		printf("Error : pcap_open_live() %s\n", errorBuffer);
		exit(1);
	}



}
