#ifndef CLICK_MARKIP6HEADER_HH
#define CLICK_MARKIP6HEADER_HH
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

class MarkIP6Header : public Element {

  int _offset;

 public:

  MarkIP6Header();
  ~MarkIP6Header();

  const char *class_name() const		{ return "MarkIP6Header"; }
  const char *port_count() const		{ return "1/2"; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  void push(int port, Packet *p);   // when a packed is pushed into this element we will handle it as follows
                                    // the first port parameter indicates the port on which the packet is pushed but we don't give something about that, also: as we have indicated above this port has only 1 input port so the port number will actually always be '0'.

 private:
  void* handleExtraHeader(void *previousHeader, uint8_t headerNumber, uint8_t &nextHeaderNumber, int &currentLocationInPacket, bool& errorEncountered, Packet* p, in6_addr sourceAddress, in6_addr destinationAddress);

  int timesDestinationHeaderSeen;   // number of times the destination header has been encountered
  int timesRoutingHeaderSeen;       // number of times the router header has been encountered
  int timesFragmentHeaderSeen;      // number of times the fragment header has been encountered
  int timesMobilityHeaderSeen;      // number of times the mobility header has been encountered
  

};

CLICK_ENDDECLS
#endif
