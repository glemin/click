/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef CLICKNET_IP6_H
#define CLICKNET_IP6_H
/* get struct in6_addr */
#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#if CLICK_LINUXMODULE
# include <net/checksum.h>
# include <linux/in6.h>
#else
# include <sys/types.h>
# include <netinet/in.h>
#endif

/* Main/Regular IPv6 Header */
struct click_ip6 {
    union {
	struct {
	    uint32_t ip6_un1_flow;	/* 0-3	 bits 0-3: version == 6	     */
					/*	 bits 4-11: traffic class    */
					/*	   bits 4-9: DSCP	     */
					/*	   bits 10-11: ECN	     */
					/*	 bits 12-31: flow label	     */
	    uint16_t ip6_un1_plen;	/* 4-5	 payload length		     */
	    uint8_t ip6_un1_nxt;	/* 6	 next header		     */
	    uint8_t ip6_un1_hlim;	/* 7	 hop limit		     */
	} ip6_un1;
	uint8_t ip6_un2_vfc;		/* 0	 bits 0-3: version == 6	     */
					/*	 bits 4-7: top 4 class bits  */
	struct {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
	    unsigned ip6_un3_v : 4;	/* 0	 version == 6		     */
	    unsigned ip6_un3_fc : 4;	/*	 header length		     */
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
	    unsigned ip6_un3_fc : 4;	/* 0	 header length		     */
	    unsigned ip6_un3_v : 4;	/*	 version == 6		     */
#endif
	} ip6_un3;


        // easy to address version which uses a byte-like access for the first 31 bits in the packet.
        struct {		
           uint8_t byte0;		/* 0-3	 version == 6	   		   */
					/* 4-7	 differentiated service (part 1)   */
					/*           4-7: DSCP (part 1) 	   */

           uint8_t byte1;		/* 8-11  differentiated service (part 2) */
					/*	     8-9: DSCP (part 2)          */
                                        /*           10-11: ECN                  */
                                        /* 12-15 flow label (part 1)           */
           uint8_t byte2;           /* 16-23 flow label (part 2)           */
           uint8_t byte3;           /* 24-31 flow label (part 3)           */
           uint16_t payload_length; // on bytes 4 and 5
	       uint8_t next_header;     // on byte 6
           uint8_t hop_limit;       // on byte 7
        } alt4;	// fourth alternative way to describe an IPv6 packet
    } ip6_ctlun;     // this contains the first 8 bytes of the packet, containing a version, traffic class, flow label, payload length and next header.
                     // it excludes the actual source and destination address.
    struct in6_addr ip6_src;	/* 8-23	 source address */
    struct in6_addr ip6_dst;	/* 24-39 dest address */
};

#define ip6_v			ip6_ctlun.ip6_un3.ip6_un3_v
#define ip6_vfc			ip6_ctlun.ip6_un2_vfc
#define ip6_flow		ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen		ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt			ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim		ip6_ctlun.ip6_un1.ip6_un1_hlim

// TODO How does this MASK/SHIFT thing work? Can a short tutorial be written about this?
#define IP6_FLOW_MASK		0x000FFFFFU
#define IP6_FLOW_SHIFT		0
#define IP6_CLASS_MASK		0x0FF00000U
#define IP6_CLASS_SHIFT		20
#define IP6_DSCP_MASK		0x0FC00000U
#define IP6_DSCP_SHIFT		22
#define IP6_V_MASK		0xF0000000U
#define IP6_V_SHIFT		28

#define IP6_CHECK_V(hdr)	(((hdr).ip6_vfc & htonl(IP6_V_MASK)) == htonl(6 << IP6_V_SHIFT))

#ifndef IP6PROTO_FRAGMENT
#define IP6PROTO_FRAGMENT 0x2c
#endif
struct click_ip6_fragment {
    uint8_t ip6_frag_nxt;
    uint8_t ip6_frag_reserved;
    uint16_t ip6_frag_offset;
#define IP6_MF		0x0001
#define IP6_OFFMASK	0xFFF8
					/*	 bits 0-12: Fragment offset  */
					/*	 bit 13-14: reserved	     */
					/*	 bit 15: More Fragment	     */
    uint32_t ip6_frag_id;
};

/* Extension headers: */

/* Hop-by-Hop Options Header */
struct click_ip6_hop_header {
    uint8_t next_header; // type of the next header (e.g. UDP is 17, or Mobility Extension header is 135).
    uint8_t hdr_ext_len; // length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
    uint8_t* options;    // variable length field, of a length such that the complete Hop-by-Hop Options header is an integer multiple of 8 octets long.
                         // contains one or more TLV-encoded options (see RFC 2460 section 4.2).
};

/* Routing Header */
/* The Routing header is used by an IPv6 source to list one or more intermediate nodes to be "visited" on the way to a packet's destination */
/* The Routing Header is identified by a Next Header value of 43 in the immediately preceding header. */
struct click_ip6_routing_header {
    uint8_t next_header; // type of the next header (e.g. UDP is 17, or Mobility Extension header is 135).
    uint8_t hdr_ext_len; // length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.
    uint8_t routing_type; // Identifier of a particular Routing header variant.
    uint8_t segments_left; // Number of route segments remaining, i.e., number of explicitly listed intermediate nodes still to be visited before reaching the final destination.
    uint8_t* type_specific_data; // Variable-length field, of format determined by the Routing Type, and of length such that the complete Routing header is an integer multiple of 8 octets long.
};

/* Destination Options Header */
struct click_ip6_destination_header {
    uint8_t next_header; // type of the next header (e.g. UDP is 17, or Mobility Extension header is 135).
    uint8_t hdr_ext_len; // length of the Destination Options header in 8-octet units, not including the first 8 octets.
    uint8_t* options; // variable-length field, of length such that the complete Destination Options heade ris an integer multiple of 8 octets long. Contains one or more TLV-encoded options, as described in section 4.2.
};

uint16_t in6_fast_cksum(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			uint16_t len,
			uint8_t proto,
			uint16_t ori_csum,
			const unsigned char *addr,
			uint16_t len2);

uint16_t in6_cksum(const struct in6_addr *saddr,
		   const struct in6_addr *daddr,
		   uint16_t len,
		   uint8_t proto,
		   uint16_t ori_csum,
		   unsigned char *addr,
		   uint16_t len2);

CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>
#endif
