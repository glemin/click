/*
 * setipecn.{cc,hh} -- element sets IP header ECN field
 * Glenn Minne
 *
 * Copyright (c) 2009 Intel Corporation
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
#include "setip6ecn.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
CLICK_DECLS

SetIP6ECN::SetIP6ECN()
{
}

SetIP6ECN::~SetIP6ECN()
{
}

int
SetIP6ECN::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String ecn;
    if (Args(conf, this, errh).read_mp("ECN", AnyArg(), ecn).complete() < 0)
	return -1;
    if (ecn.length() == 1 && ecn[0] >= '0' && ecn[0] <= '3')
	_ecn = ecn[0] - '0'; // subtract zero ASCII character since we are working with integers, not with chars
    else if (ecn.equals("no", 2) || ecn.equals("-", 1))
	_ecn = 0;
    else if (ecn.equals("ect1", 4) || ecn.equals("ECT(1)", 6))
	_ecn = 1;
    else if (ecn.equals("ect2", 4) || ecn.equals("ECT(0)", 6))
	_ecn = 2;
    else if (ecn.equals("ce", 2) || ecn.equals("CE", 2))
	_ecn = 3;
    else
	return errh->error("bad ECN argument");
    return 0;
}

Packet *
SetIP6ECN::simple_action(Packet *p)
{
    assert(p->has_network_header());
    WritablePacket *q;
    if (!(q = p->uniqueify()))
	return 0;
    click_ip6 *ip = q->ip6_header();
    ip->ip6_ctlun.alt4.byte1 = ((ip->ip6_ctlun.alt4.byte1 & 0b11001111) | (_ecn << 4)); // This first sets the original ECN bits to 00 with & 0b11001111, after which the two new ECN bits are set with an OR operation. Our two bits are internally saved as 00000xx with our x's always being '1' or '0'. Because they need to come on position 3 and 4 of our byte and not on position 7 or 8, they need to be shifted 4 places to the left first to get them in the position where they finally need to be of byte 1 of our IPv6 packet, before we can OR.
    return q;
}

void
SetIP6ECN::add_handlers()
{
    add_read_handler("ecn", read_keyword_handler, "0 ECN", Handler::CALM);
    add_write_handler("ecn", reconfigure_keyword_handler, "0 ECN");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetIP6ECN)
ELEMENT_MT_SAFE(SetIP6ECN)
