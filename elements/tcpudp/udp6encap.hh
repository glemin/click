#ifndef CLICK_UDP6ENCAP_HH
#define CLICK_UDP6ENCAP_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/udp.h>
#include <click/ip6address.hh>
CLICK_DECLS

/*
=c

UDP6Encap(SRC, SPORT, DST, DPORT, PROTO)

=s udp

encapsulates packets in UDP headers

=d

Encapsulates each incoming packet in a UDP packet with source port SPORT, 
and destination port DPORT. The UDP checksum is always calculated; this
is mandatory in IPv6.

The UDPEncap element adds a UDP header.

The Strip element can be used by the receiver to get rid of the
encapsulation header.

Users also need to pass the IPv6 source address SRC, IPv6 destination
address DST and the next protocol value PROTO (e.g. 0 for HOP-OPT,
43 for IPv6-Route or 60 for IPv6-Opts); UDPEncap needs this information
to calculate UDP's checksum which is when used in combination with IPv6
calculated over a "pseudo-header", which is basically an UDP header
preeceded by some information of the fixed IPv6 header.

=e
  UDP6Encap(3ffe:1900:4545:3:200:f8ff:fe21:67cf, 1234, fe80::200:f8ff:fe21:67cf, 1235, 43)

=h sport read/write

Returns or sets the SPORT source port argument.

=h dport read/write

Returns or sets the DPORT destination port argument.

=a Strip, IPEncap, IP6Encap, HopByHopEncap
*/

class UDP6Encap : public Element { public:

    UDP6Encap() CLICK_COLD;
    ~UDP6Encap() CLICK_COLD;

    const char *class_name() const	{ return "UDP6Encap"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const		{ return "A"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const	{ return true; }
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    IP6Address _sourceAddress;
    IP6Address _destinationAddress;
    uint16_t _sport;
    uint16_t _dport;
    uint8_t _protocol;

#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    bool _aligned;
    bool _checked_aligned;
#endif
    atomic_uint32_t _id;

    static String read_handler(Element *, void *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
