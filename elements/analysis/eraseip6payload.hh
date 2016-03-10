// -*- c-basic-offset: 4 -*-
#ifndef CLICK_ERASEIP6PAYLOAD_HH
#define CLICK_ERASEIP6PAYLOAD_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
CLICK_DECLS

/*
=c

EraseIP6Payload()

=s ip6

erases IPv6 packet payload

=d

Erases all TCP or UDP payload in incoming packets, leaves ICMP payloads unaffected 
and drops all other payloads.
If the payload is TCP or UDP, all payload bytes are set to zero.
If the payload is ICMP, no erasing is done. 
For all other payloads, the packet is dropped.

=a AnonymizeIP6Addr */

class EraseIP6Payload : public Element { public:

    EraseIP6Payload() CLICK_COLD;
    ~EraseIP6Payload() CLICK_COLD;

    const char *class_name() const	{ return "EraseIP6Payload"; }
    const char *port_count() const	{ return PORTS_1_1; }

    Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif
