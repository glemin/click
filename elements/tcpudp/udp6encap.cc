/*
 * udp6encap.{cc,hh} -- Element encapsulates packet in UDP header.
 *                      Use this element over udp encap when it's
 *                      underlying network protocol is IPv6
 * Glenn Minne
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2007 Regents of the University of California
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
#include "udp6encap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/standard/alignmentinfo.hh>
#include <clicknet/ip6.h>
CLICK_DECLS

UDP6Encap::UDP6Encap()
{
    _id = 0;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    _checked_aligned = false;
#endif
}

UDP6Encap::~UDP6Encap()
{
}

int
UDP6Encap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
    .read_mp("SRC", _sourceAddress)
	.read_mp("SPORT", IPPortArg(IP_PROTO_UDP), _sport)
    .read_mp("DST", _destinationAddress)
	.read_mp("DPORT", IPPortArg(IP_PROTO_UDP), _dport)
    .read_mp("PROTO", _protocol)
	.complete() < 0)
	return -1;

#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    if (!_checked_aligned) {			// TODO wat is dit? => we gebruiken dit enkel als FAST_CHECKSUM aangevinkt is
	int ans, c, o;
	ans = AlignmentInfo::query(this, 0, c, o);
	_aligned = (ans && c == 4 && o == 0);
	if (!_aligned)
	    errh->warning("IP header unaligned, cannot use fast IP checksum");
	if (!ans)
	    errh->message("(Try passing the configuration through %<click-align%>.)");
	_checked_aligned = true;
    }
#endif

    return 0;
}

Packet *
UDP6Encap::simple_action(Packet *p_in)
{
  WritablePacket *p = p_in->push(sizeof(click_udp));        // make room to add the UDP header part in the front (that is, usually just before the packet data)
  click_udp *udp = reinterpret_cast<click_udp *>(p->data());

#if !HAVE_INDIFFERENT_ALIGNMENT
  assert((uintptr_t)ip % 4 == 0);
#endif
  // set up UDP header
  udp->uh_sport = htons(_sport);
  udp->uh_dport = htons(_dport);
  udp->uh_ulen = htons(p->length());
  udp->uh_sum = 0;
  udp->uh_sum= in6_cksum((in6_addr*) _sourceAddress.data32() /* source address of fixed ipv6 header */, (in6_addr*) _destinationAddress.data32() /* destination address of fixed ipv6 header */, 0 /* TODO */ /* size of 3rd layer protocol + size of data */, _protocol /* next header field of fixed ipv6 header */, click_in_cksum((unsigned char *)udp, p->length()), p->data() /* data of 3rd layer protocol*/, htons(sizeof(click_udp)) /* htons(...)'d size of 3rd layer protocol */);

  return p;
}

String UDP6Encap::read_handler(Element *e, void *thunk)
{
    UDP6Encap *u = static_cast<UDP6Encap *>(e);
    switch ((uintptr_t) thunk) {
      case 0:
	return String(ntohs(u->_sport));
      case 1:
	return String(ntohs(u->_dport));
      default:
	return String();
    }
}

void UDP6Encap::add_handlers()
{
    add_read_handler("sport", read_handler, 0);
    add_write_handler("sport", reconfigure_keyword_handler, "0 SPORT");
    add_read_handler("dport", read_handler, 1);
    add_write_handler("dport", reconfigure_keyword_handler, "1 DPORT");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(UDP6Encap)
ELEMENT_MT_SAFE(UDP6Encap)
