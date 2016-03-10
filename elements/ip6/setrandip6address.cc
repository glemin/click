/*
 * setrandip6address.{cc,hh} -- element sets destination address annotation to a random IP address
 * Glenn Minne
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "setrandip6address.hh"
#include <click/args.hh>

CLICK_DECLS

SetRandIP6Address::SetRandIP6Address()
{
  _limit = -1;	// the number of distinct IP addresses we are going to generate
  _addrs = 0;   // in this field, those addresses will be stored, of type IPAddress* and memory will be allocated dynamically.
}

SetRandIP6Address::~SetRandIP6Address()
{
}

int
SetRandIP6Address::configure(Vector<String> &conf, ErrorHandler *errh)
{
	_limit = -1; // _limit = -1 means infinity
    int ret = Args(conf, this, errh)
	.read_mp("PREFIX", IP6PrefixArg(true), _address, _mask)
	.read_p("LIMIT", _limit)
	.read_p("UNICAST_ONLY", _unicast_only) // TODO is there a special bool argument?
	.read_p("MULTICAST_ONLY", _multicast_only).complete(); // TODO is there a special bool argument?

    // If we only work with a distinct pool of IP addresses, we generate them in advance, out of this pool we pick an IP address at random then.
    if(_limit >= 0) {	// we have a certain number of distinct addresses that need to be generated, it is not inifit
    	_addrs = new IP6Address [_limit] ();

    	for(int i = 0; i < _limit; i++)
    		_addrs[i] = pick();		// pick every round an other address
    }

    click_random_srandom();	// This functions sets the start seed for our click_random() function.

    return(ret);
}

IP6Address
SetRandIP6Address::pick()
{

	uint32_t first_part = click_random();
	uint32_t second_part = click_random();
	uint32_t third_part = click_random();
	uint32_t fourth_part = click_random();


	unsigned char* ip_address_pointer = new unsigned char[16];

	memcpy(ip_address_pointer, &first_part, 4);
	memcpy(ip_address_pointer + 4, &second_part, 4);
	memcpy(ip_address_pointer + 8, &third_part, 4);
	memcpy(ip_address_pointer + 12, &fourth_part, 4);

	IP6Address generated_address(ip_address_pointer);

	delete ip_address_pointer;

	return(generated_address);
}

Packet *
SetRandIP6Address::simple_action(Packet *p)
{
  IP6Address ipa;

  if(_limit > 0) {
      ipa = _addrs[click_random(0, _limit - 1)];	// we pick at random one of our precalculated distinct IP addresses
  } else {	// no limit imposed, so we just pick a random address
      ipa = pick();
  }

  click_chatter("the ip address is %s", ipa.unparse().c_str());

  p->set_dst_ip6_anno(ipa);

  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetRandIP6Address)
ELEMENT_MT_SAFE(SetRandIP6Address)
