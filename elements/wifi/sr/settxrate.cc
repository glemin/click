/*
 * settxrate.{cc,hh} -- sets wifi txrate annotation on a packet
 * John Bicket
 *
 * Copyright (c) 2003 Massachusetts Institute of Technology
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
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include "settxrate.hh"
#include <clicknet/ether.h>
CLICK_DECLS

SetTXRate::SetTXRate()
  : Element(1, 1)
{
  MOD_INC_USE_COUNT;
}

SetTXRate::~SetTXRate()
{
  MOD_DEC_USE_COUNT;
}

int
SetTXRate::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _auto_l = 0;
  _ett_l = 0;
  _rate = 0;
  _et = 0;
  if (cp_va_parse(conf, this, errh,
		  cpKeywords, 
		  "ETHTYPE", cpUnsigned, "Ethernet encapsulation type", &_et,
		  "RATE", cpUnsigned, "rate", &_rate, 
		  "AUTO", cpElement, "AutoTXRate element", &_auto_l,
		  "ETT", cpElement, "ETTMetric element", &_ett_l,
		  0) < 0) {
    return -1;
  }

  switch (_rate) {
  case 0:
    /* fallthrough */
  case 1:
    /* fallthrough */
  case 2:
    /* fallthrough */
  case 5:
    /* fallthrough */
  case 11:
    break;
  default:
    return errh->error("RATE must be 0, 1,2,5, or 11");
  }

  if (_auto_l && _auto_l->cast("AutoTXRate") == 0) {
    return errh->error("AUTO element is not a AutoTXRate");
  }


  if (_ett_l && _ett_l->cast("ETTMetric") == 0) {
    return errh->error("ETT element is not a ETTMetric");
  }

  if (_auto_l && _ett_l) {
    return errh->error("can't specify both ETT and AUTO");
  }
  _auto = (_auto_l) || (_ett_l);

  return 0;
}

Packet *
SetTXRate::simple_action(Packet *p_in)
{
  click_ether *eh = (click_ether *) p_in->data();

  if (_et && eh->ether_type != htons(_et)) {
    return p_in;
  }

  SET_WIFI_FROM_CLICK(p_in);
  if (_auto) {
    EtherAddress dst = EtherAddress(eh->ether_dhost);
    int rate = 0;
    if (_auto_l) {
      rate = _auto_l->get_tx_rate(dst);
    } else if (_ett_l) {
      rate = _ett_l->get_tx_rate(dst);
    }
    
    if (rate) {
      SET_WIFI_RATE_ANNO(p_in, rate);  
      return p_in;
    }
  }
  SET_WIFI_RATE_ANNO(p_in, _rate);  
  return p_in;
}
String
SetTXRate::rate_read_handler(Element *e, void *)
{
  SetTXRate *foo = (SetTXRate *)e;
  return String(foo->_rate) + "\n";
}

int
SetTXRate::rate_write_handler(const String &arg, Element *e,
			      void *, ErrorHandler *errh) 
{
  SetTXRate *n = (SetTXRate *) e;
  int b;

  if (!cp_integer(arg, &b))
    return errh->error("`rate' must be an integer");
  switch (b) {
  case 0:
    /* fallthrough */
  case 1:
    /* fallthrough */
  case 2:
    /* fallthrough */
  case 5:
    /* fallthrough */
  case 11:
    break;
  default:
    return errh->error("RATE must be 0, 1,2,5, or 11");
  }
  n->_rate = b;
  return 0;
}

int
SetTXRate::auto_write_handler(const String &arg, Element *e,
			      void *, ErrorHandler *errh) 
{
  SetTXRate *n = (SetTXRate *) e;
  bool b;

  if (!cp_bool(arg, &b))
    return errh->error("`auto' must be an boolean");
  
  if (b && !((n->_auto_l) || (n->_ett_l))) {
    return errh->error("`auto' is true but no auto_rate element configured");
  }

  n->_auto = b;
  return 0;
}
String
SetTXRate::auto_read_handler(Element *e, void *)
{
  SetTXRate *foo = (SetTXRate *)e;
  if (foo->_auto && (foo->_auto_l || foo->_ett_l)) {
    return String("true") + "\n";
  }
  return String("false") + "\n";
}

void
SetTXRate::add_handlers()
{
  add_default_handlers(true);
  add_read_handler("rate", rate_read_handler, 0);
  add_write_handler("rate", rate_write_handler, 0);
  add_read_handler("auto", auto_read_handler, 0);
  add_write_handler("auto", auto_write_handler, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetTXRate)
