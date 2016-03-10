#ifndef CLICK_HOPBYHOPENCAP_HH
#define CLICK_HOPBYHOPENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * MarkIP6Header([OFFSET])
 * =s ip6
 *
 * =d
 *
 * Marks packets as IP6 packets by setting the IP6 Header annotation. The IP6
 * header starts OFFSET bytes into the packet. Default OFFSET is 0. Does not
 * check length fields for sanity or shorten packets to the IP length; use
 * CheckIPHeader or CheckIPHeader2 for that.
 *
 * =a CheckIP6Header, CheckIP6Header2, StripIP6Header */

class HopByHopEncap : public Element {

  uint8_t _next_header; // next header following the IPv6 Hop-by-Hop extension header.
  int _router_alert_option = -1; // if our Hop-By-Hop Extension header happens to be a router alert then this value represents the value of the router alert option (RFC 2711) 
                                 // 0 means Multicast Listener Discovery message, 1 means RSVP message, 2 means Active Network message, 3-65535 are reserved to IANA for further use.
                                 // -1 is not defined in the RFC but means here that the value is still undefined.

 public:

  HopByHopEncap();
  ~HopByHopEncap();

  const char *class_name() const		{ return "HopByHopEncap"; }
  const char *port_count() const		{ return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif
