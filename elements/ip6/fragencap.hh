#ifndef CLICK_FRAGENCAP_HH
#define CLICK_FRAGENCAP_HH
#include <click/element.hh>
CLICK_DECLS

/*
 * =c
 * FragEncap ( ...... )
 * =s ip6
 *
 * =d
 *
 * Encapsulates a packet in an IPv6 Fragment extension header. This element is only used for testing purposes. Prefer to use a more specialised element in stead.
 *
 * =a CheckIP6Header, CheckIP6Header2, StripIP6Header */

class FragEncap : public Element {

  uint8_t _nextHeader;             // next header following the IPv6 Fragment extension header.
  uint16_t _fragOffset;            // fragment offset (actually only 13 bit long but there don't exist 13 bit fields in C++)
                                    // we will save the data internally in the first 13  bits of this struct
  bool _m;                          // the M flag, indicates the end of a the original packet that was to big. 1 means more parts to follow. 0 means we have had 
                                    // all fragmented parts.
  uint32_t _id;                     // the ID that is particular to this fragmentation task.

 public:

  FragEncap();
  ~FragEncap();

  const char *class_name() const		{ return "FragEncap"; }
  const char *port_count() const		{ return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *simple_action(Packet *);

};

CLICK_ENDDECLS
#endif
