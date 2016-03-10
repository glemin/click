/*
 * markip6ce.{cc,hh} -- element marks IP header ECN CE bit
 * Glenn Minne
 *
 * Copyright (c) 2001 International Computer Science Institute
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
#include "markip6ce.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
CLICK_DECLS

MarkIP6CE::MarkIP6CE()
{
    _drops = 0;
}

MarkIP6CE::~MarkIP6CE()
{
}

int
MarkIP6CE::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _force = false;
    return Args(conf, this, errh).read_p("FORCE", _force).complete();
}

Packet *
MarkIP6CE::simple_action(Packet *p)
{
    assert(p->has_network_header());
    const click_ip6 *iph = p->ip6_header();
    if (!_force) {
        if ((iph->ip6_ctlun.alt4.byte1 | 0b11001111) == (0b11001111)) {	// CE is not enabled (the field contains 00), and as such the packet needs to be killed.
            p->kill();
            return 0;
        }    
    }


    if ((iph->ip6_ctlun.alt4.byte1 | 0b11001111) == (0b11111111)) {          // CE is already fully enabled (the field contains 11), and as such nothing needs to be done and the packet can just be forwarded;
        return p;
    }



    // In all other cases, the bits needs to be written into the packet and we first need to change our packet into a WritablePacket.
    WritablePacket *q = p->uniqueify();
    if (!(q = p->uniqueify()))
	return 0;

    click_ip6 *q_iph = q->ip6_header();
    q_iph->ip6_ctlun.alt4.byte1 |= 0b00110000;	// set the CE field to CE fully enabled (the field contains 11), by using and OR operation with a bit string that contains 11 on the position where CE is located.

    return q;
}

void
MarkIP6CE::add_handlers()
{
    add_data_handlers("drops", Handler::OP_READ, &_drops);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MarkIP6CE)
ELEMENT_MT_SAFE(MarkIP6CE)
