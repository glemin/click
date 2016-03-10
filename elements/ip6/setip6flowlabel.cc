/*
 * setip6flowlabel.{cc,hh} -- element sets IP6 flow label field
 * Glenn Minne
 *
 * Copyright (c) 2002 Massachusetts Institute of Technology
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
#include "setip6flowlabel.hh"
#include <clicknet/ip6.h>
#include <click/args.hh>
#include <click/error.hh>
CLICK_DECLS

SetIP6FlowLabel::SetIP6FlowLabel()
{
}

SetIP6FlowLabel::~SetIP6FlowLabel()
{
}

int
SetIP6FlowLabel::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned dscp_val;
    if (Args(conf, this, errh).read_mp("FlowLabel", _flowLabel).complete() < 0)
	    return -1;
    if (_flowLabel > 4194303)
	    return errh->error("flow label out of range");

    return 0;
}


inline Packet *
SetIP6FlowLabel::smaction(Packet *p_in)
{
    WritablePacket *p = p_in->uniqueify();
    assert(p->has_network_header());
    click_ip6 *ip6 = p->ip6_header();
    
    ip6->ip6_ctlun.alt4.byte1 = (ip6->ip6_ctlun.alt4.byte1 & 0b11110000) | _flowLabel >> 16; /* first set last 4 bits to zero. Then insert the new Flow Label bits in */
    ip6->ip6_ctlun.alt4.byte2 = _flowLabel >> 8;
    ip6->ip6_ctlun.alt4.byte3 = _flowLabel;

    return p;
}

void
SetIP6FlowLabel::push(int, Packet *p)
{
  if ((p = smaction(p)) != 0)
    output(0).push(p);
}

Packet *
SetIP6FlowLabel::pull(int)
{
  Packet *p = input(0).pull();
  if (p)
    p = smaction(p);
  return p;
}

void
SetIP6FlowLabel::add_handlers()
{
    add_read_handler("flowlabel", read_keyword_handler, "0 FlowLabel", Handler::CALM);
    add_write_handler("flowlabel", reconfigure_keyword_handler, "0 FlowLabel");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetIP6FlowLabel)
ELEMENT_MT_SAFE(SetIP6FlowLabel)
