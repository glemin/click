/*
 * fragencap.{cc,hh} -- Encapsulates packet in a Fragment IPv6 extension header.
 *                      This element is used for testing purposes only.
 * Glenn Minne
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
#include "fragencap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6_extension.h>
CLICK_DECLS

FragEncap::FragEncap()
{
}

FragEncap::~FragEncap()
{
}

int
FragEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  return Args(conf, this, errh).read_p("PROTO", _nextHeader)
                               .read_mp("FRAG_OFFSET", _fragOffset)        // fragment offset
                               .read_mp("M", _m)                            // M
                               .read_mp("ID", _id)                          // identification
                               .complete();
}

Packet*
FragEncap::simple_action(Packet *p)
{
    WritablePacket* q = p->push(sizeof(FragmentationHeader)); // make room for the new Hop-by-Hop extension header

    if (!q)
      return 0;

    FragmentationHeader* fragmentationExtensionHeader = reinterpret_cast<FragmentationHeader*>(q->data());

    // set the values of the Fragment extension header
    fragmentationExtensionHeader->next_header = _nextHeader;


    fragmentationExtensionHeader->fragment_offset_part1 = _fragOffset;    // implicit cast
    fragmentationExtensionHeader->fragment_offset_part2_and_reserved_and_M = _fragOffset << 8; // to get the remaining 5 bits

   
    // TODO needs to be I guess finished ; is not yet working I think

    return q;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(FragEncap)
