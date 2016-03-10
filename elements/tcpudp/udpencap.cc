/*
 * udpencap.{cc,hh} -- element encapsulates packet in UDP/IP header
 * Benjie Chen, Eddie Kohler
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
#include "udpencap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/standard/alignmentinfo.hh>
CLICK_DECLS

UDPEncap::UDPEncap()
    : _cksum(true)
{
    _id = 0;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    _checked_aligned = false;
#endif
}

UDPEncap::~UDPEncap()
{
}

int
UDPEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
    IPAddress saddr;
    uint16_t sport, dport;
    bool cksum;
    String daddr_str;

    if (Args(conf, this, errh)
	.read_mp("SPORT", IPPortArg(IP_PROTO_UDP), sport)
	.read_mp("DPORT", IPPortArg(IP_PROTO_UDP), dport)
	.read_p("CHECKSUM", BoolArg(), cksum)
	.complete() < 0)
	return -1;

    _sport = htons(sport);
    _dport = htons(dport);

#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    if (!_checked_aligned) {			// TODO wat is dit?
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
UDPEncap::simple_action(Packet *p_in)
{
  WritablePacket *p = p_in->push(sizeof(click_udp));
  click_udp *udp = reinterpret_cast<click_udp *>(p->data());

#if !HAVE_INDIFFERENT_ALIGNMENT
  assert((uintptr_t)ip % 4 == 0);	// TODO wat is dit?
#endif
  // set up UDP header
  udp->uh_sport = _sport;
  udp->uh_dport = _dport;
  uint16_t len = p->length();
  udp->uh_ulen = htons(len);
  udp->uh_sum = 0;
  if (_cksum) {
    udp->uh_sum = click_in_cksum((unsigned char *)udp, len);
  }

  return p;
}

String UDPEncap::read_handler(Element *e, void *thunk)
{
    UDPEncap *u = static_cast<UDPEncap *>(e);
    switch ((uintptr_t) thunk) {
      case 0:
	return String(ntohs(u->_sport));
      case 1:
	return String(ntohs(u->_dport));
      default:
	return String();
    }
}

void UDPEncap::add_handlers()
{
    add_read_handler("sport", read_handler, 0);
    add_write_handler("sport", reconfigure_keyword_handler, "0 SPORT");
    add_read_handler("dport", read_handler, 1);
    add_write_handler("dport", reconfigure_keyword_handler, "1 DPORT");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(UDPEncap)
ELEMENT_MT_SAFE(UDPEncap)
