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
			u_long	TotPkts;	  can't oflow for 79 hrs on ether
			u_long	TotAccepted;  count accepted by filter
			u_long	TotDrops;	  count of dropped packets
			long	TotMissed;	  missed by i/f during this run
			long	OrigMissed;	  missed by i/f before this run
			char	* device;	  device name
			int	timeout;		  timeout for buffering
			int	must_clear;		  stuff we must clear when we close */
			struct pcap * next;	  list of open pcaps that need stuff cleared on close
		#ifdef linux
			int	sock_packet;	  using Linux 2.0 compatible interface */
			int	cooked;			  using SOCK_DGRAM rather than SOCK_RAW */
			int	ifindex;		  interface index of device we're bound to */
			int	lo_ifindex;		  interface index of the loopback device
			u_int	packets_read; count of packets read with recvfrom()
			bpf_u_int32 oldmode;  mode to restore when turning monitor mode off
			u_int	tp_version;	  version of tpacket_hdr for mmaped ring
			u_int	tp_hdrlen;    hdrlen of tpacket_hdr for mmaped ring
		#endif linux

#ifdef HAVE_DAG_API
#ifdef HAVE_DAG_STREAMS_API
		u_char	*dag_mem_bottom;	/* DAG card current memory bottom pointer */
		u_char	*dag_mem_top;	/* DAG card current memory top pointer */
#else /* HAVE_DAG_STREAMS_API */
		void	*dag_mem_base;	/* DAG card memory base address */
		u_int	dag_mem_bottom;	/* DAG card current memory bottom offset */
		u_int	dag_mem_top;	/* DAG card current memory top offset */
#endif /* HAVE_DAG_STREAMS_API */
		int	dag_fcs_bits;	/* Number of checksum bits from link layer */
		int	dag_offset_flags; /* Flags to pass to dag_offset(). */
		int	dag_stream;	/* DAG stream number */
		int	dag_timeout;	/* timeout specified to pcap_open_live.
					 * Same as in linux above, introduce
					 * generally? */
#endif /* HAVE_DAG_API */
#ifdef HAVE_ZEROCOPY_BPF
		   /*
			* Zero-copy read buffer -- for zero-copy BPF.  'buffer' above will
			* alternative between these two actual mmap'd buffers as required.
			* As there is a header on the front size of the mmap'd buffer, only
			* some of the buffer is exposed to libpcap as a whole via bufsize;
			* zbufsize is the true size.  zbuffer tracks the current zbuf
			* assocated with buffer so that it can be used to decide which the
			* next buffer to read will be.
			*/
		   u_char *zbuf1, *zbuf2, *zbuffer;
		   u_int zbufsize;
		   u_int zerocopy;
		   u_int interrupted;
		   struct timespec firstsel;
		   /*
			* If there's currently a buffer being actively processed, then it is
			* referenced here; 'buffer' is also pointed at it, but offset by the
			* size of the header.
			*/
		   struct bpf_zbuf_header *bzh;
#endif /* HAVE_ZEROCOPY_BPF */



#ifdef HAVE_REMOTE
	/*!
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
	*/
		unsigned int TotNetDrops;       //!< keeps the number of packets that have been dropped by the network
	/*!
		\brief It keeps the number of packets that have been received by the application.

		Packets dropped by the kernel buffer are not counted in this variable. The variable is always
		equal to (TotAccepted - TotDrops), exept for the case of remote capture, in which we have also
		packets in fligh, i.e. that have been transmitted by the remote host, but that have not been
		received (yet) from the client. In this case, (TotAccepted - TotDrops - TotNetDrops) gives a
		wrong result, since this number does not corresponds always to the number of packet received by
		the application. For this reason, in the remote capture we need another variable that takes
		into account of the number of packets actually received by the application.
	*/
		unsigned int TotCapt;
#endif /* HAVE_REMOTE */

	};



	*/
	pcap_t



}
