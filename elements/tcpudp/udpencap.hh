#ifndef CLICK_UDPENCAP_HH
#define CLICK_UDPENCAP_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/udp.h>
CLICK_DECLS

/*
=c

UDPIPEncap(SRC, SPORT, DST, DPORT [, CHECKSUM])

=s udp

encapsulates packets in UDP headers

=d

Encapsulates each incoming packet in a UDP packet with source port SPORT, 
and destination port DPORT. The UDP checksum is calculated if CHECKSUM? is
true; it is true by default.

The UDPEncap element adds a UDP header.

The Strip element can be used by the receiver to get rid of the
encapsulation header.

=e
  UDPEncap(1234, 1235)

=h sport read/write

Returns or sets the SPORT source port argument.

=h dport read/write

Returns or sets the DPORT destination port argument.

=a Strip, IPEncap, IP6Encap, HopByHopEncap
*/

class UDPEncap : public Element { public:

    UDPEncap() CLICK_COLD;
    ~UDPEncap() CLICK_COLD;

    const char *class_name() const	{ return "UDPEncap"; }
    const char *port_count() const	{ return PORTS_1_1; }
    const char *flags() const		{ return "A"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const	{ return true; }
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    uint16_t _sport;
    uint16_t _dport;
    bool _cksum;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    bool _aligned;
    bool _checked_aligned;
#endif
    atomic_uint32_t _id;

    static String read_handler(Element *, void *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
