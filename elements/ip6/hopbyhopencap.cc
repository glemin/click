/*
 * hopbyhopencap.{cc,hh} -- encapsulates packet in a Hop-by-Hop IPv6 extension header
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
#include "hopbyhopencap.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6_extension.h>
CLICK_DECLS

HopByHopEncap::HopByHopEncap()
{
}

HopByHopEncap::~HopByHopEncap()
{
}

int
HopByHopEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int returnValue = Args(conf, this, errh).read_p("PROTO", _next_header)
                               .read_p("ROUTER_ALERT", _router_alert_option)
                               .complete();
  if (_router_alert_option > -1) { // this means the router alert option is used
    if (_router_alert_option < 1 || _router_alert_option > 65535) return errh->error("Router Alert option should be between 1 and 65535 (RFC 2711)"); // incorrect router alert value gives an error
  }
  return returnValue;   
}

Packet *
HopByHopEncap::simple_action(Packet *p)
{
  click_chatter("de waarde is %i", _next_header);

  if (_router_alert_option >= 1) { // this means it is not -1 and that Router Alert is configured

    struct Router_Alert_Header {  // This is a particular Hop-By-Hop Extension header which contains two different options.
        ////////////////////////////////////////////////////////////////
        // here is the general Hop-by-Hop header part without options //
        ////////////////////////////////////////////////////////////////
        uint8_t next_header; // type of the next header (e.g. UDP is 17, or Mobility Extension header is 135).
        uint8_t hdr_ext_len; // length of the Hop-by-Hop Options header in 8-octet units, not including the first 8 octets.

        //////////
        // what will follow are 2 options: the router alert option AND a padding option //
        //////////

        ///////////////////////////////////////////////
        // here follows the Router Alert Option part //
        ///////////////////////////////////////////////
        uint8_t option_type1;
        uint8_t opt_data_len1;
        uint16_t option_data1;

        //////////////////////////////////////////////////////////////////////////////////////////
        // here follows the padN Option part; we need padding because we need at least 8 octets //
        //////////////////////////////////////////////////////////////////////////////////////////
        uint8_t option_type2;
        uint8_t op_data_len2;

    };

    WritablePacket *q = p->push(sizeof(Router_Alert_Header)); // make room for the new Hop-by-Hop extension header

    if (!q)
      return 0;

    Router_Alert_Header *hop_by_hop_extension_header = reinterpret_cast<Router_Alert_Header *>(q->data());

    // set the values of the Hop-by-Hop extension header
    hop_by_hop_extension_header->next_header = _next_header;
    hop_by_hop_extension_header->hdr_ext_len = 0; // it is 0 because the first 8 octets don't count and we have only 8 octets in total.
    hop_by_hop_extension_header->option_type1 = 0b00000101; // this is the code for the Router Alert Option type, first two zeroes indicate that nodes not recognizing this option type, should skip over this option and continue processing the header.
    hop_by_hop_extension_header->opt_data_len1 = 0b00000010; // this is decimal for 2, the length of this option is 2 bytes or equivalently 16 bits.
    hop_by_hop_extension_header->option_data1 = htons(_router_alert_option); // this is given by the user, it can be something as MLD or RSVP.
    
    hop_by_hop_extension_header->option_type2 = 1; // means that we use the padN option
    hop_by_hop_extension_header->op_data_len2 = 0; // a padding of 2 bytes is just enough, 0 extra padding bytes required

    click_chatter("de hop_by_hop_extension_header->next_header = %i", hop_by_hop_extension_header->next_header);

    return q;

  }

  return p; // nothing happened, might need to return an error? (returning nothing seems odd)
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HopByHopEncap)
