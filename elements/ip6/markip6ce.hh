#ifndef CLICK_MARKIP6CE_HH
#define CLICK_MARKIP6CE_HH
#include <click/element.hh>
#include <click/atomic.hh>
CLICK_DECLS

/*
=c

MarkIP6CE([FORCE])

=s ip6

sets IPv6 packets' ECN field to Congestion Experienced

=d

Expects IPv6 packets as input.  Sets each incoming packet's ECN field to
Congestion Experienced (value 3), and passes the packet to output 0. Packets 
whose ECN field is zero (not ECN-capable) are dropped unless the optional 
FORCE argument is true. */

class MarkIP6CE : public Element { public:

    MarkIP6CE() CLICK_COLD;
    ~MarkIP6CE() CLICK_COLD;

    const char *class_name() const		{ return "MarkIP6CE"; }
    const char *port_count() const		{ return PORTS_1_1; }

    int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:

    bool _force;
    atomic_uint32_t _drops;

};

CLICK_ENDDECLS
#endif
