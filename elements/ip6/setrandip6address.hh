#ifndef SetRandIP6Address_hh
#define SetRandIP6Address_hh
#include <click/element.hh>
#include <click/ip6address.hh>
CLICK_DECLS

/*
 * =c
 * SetRandIP6Address(PREFIX, [LIMIT])
 * =s ip6
 * sets destination IPv6 address annotations randomly
 * =d
 * Set the destination IPv6 address annotation to a random number within
 * the specified PREFIX.
 *
 * If LIMIT is given, at most LIMIT distinct addresses will be generated.
 *
 * =a StoreIP6Address, GetIP6Address, SetIP6Address
 */

class SetRandIP6Address : public Element {

  IP6Address _address;	// TODO the IP address that is created lastly????
  IP6Address _mask;		// TODO something to do with the prefix that is read???????
  int _limit;	// number of distinct IPv6 addresses
  IP6Address *_addrs;	// list of multicast addresses that need to be generated
  bool _unicast_only;	// true if only unicast packets are generated
  bool _multicast_only;	// true if only multicast packets are generated

 public:

  SetRandIP6Address() CLICK_COLD;
  ~SetRandIP6Address() CLICK_COLD;

  const char *class_name() const	{ return "SetRandIP6Address"; }
  const char *port_count() const	{ return PORTS_1_1; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *simple_action(Packet *);
  IP6Address pick();
};

CLICK_ENDDECLS
#endif
