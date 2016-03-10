/*
 * storeip6address.{cc,hh} -- element stores IPv6 destination annotation into
 * packet
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
#include "storeip6address.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
CLICK_DECLS

StoreIP6Address::StoreIP6Address()
{
}

StoreIP6Address::~StoreIP6Address()
{
}

int
StoreIP6Address::configure(Vector<String> &conf, ErrorHandler *errh)
{

    String offset;	// the offset to be read; can be equal to src or dst in stead of a number, in which case this has a special meaning.
    int r;		// reply
    _src_set = false;
    _dst_set = false;

    if (conf.size() == 1) {
	r = Args(conf, this, errh).read_mp("OFFSET", WordArg(), offset).complete();
        _address_given = false;
    } else if (conf.size() == 2) {
	r = Args(conf, this, errh).read_mp("ADDR", _address).read_mp("OFFSET", WordArg(), offset).complete();
        _address_given = true;
    } else { // conf size should be 1 or 2
        return -1;
    }

    if (r < 0) { // a parse error occured, we should stop and return an error.
        return r;
    }

    /* translate src and dst into their actual number counterparts */
    if (offset.lower() == "src") {
        click_chatter("we zitten bij src");
        _src_set = true;
    } else if (offset.lower() == "dst") {
    	_dst_set = true;
    } else { // normal parsing needs to be done
         bool parseErrors = IntArg().parse(offset, _offset); //parse offset and place it in _offset
         if (!parseErrors || _offset < 0) { // _offset should not be negative? why? does this have a specific meaning? should there be a cap on how far negative you can go with the offset?
             return -1;
         }
    }
    return 0;

    /*

    int r;
    _use_address = conf.size() > 1;
    if (!_use_address)
	r = Args(conf, this, errh).read_mp("OFFSET", WordArg(), offset).complete();
    else
	r = Args(conf, this, errh).read_mp("ADDR", _address)
	    .read_mp("OFFSET", WordArg(), offset).complete();
    if (r < 0)
	return r;
    if (offset.lower() == "src")
	_offset = -12;
    else if (offset.lower() == "dst")
	_offset = -16;
    else if (!IntArg().parse(offset, _offset) || _offset < 0)
	return errh->error("type mismatch: OFFSET requires integer");
    return 0;

    */
}

Packet *
StoreIP6Address::simple_action(Packet *p)
{
	if (!_address_given) {		// if no address was explicitely given, we need to read it in via p->dst_ip6_anno()

		_address = IP6Address(p->dst_ip6_anno());
        	click_chatter("** het adres is %s", _address.unparse().c_str());
	}

	WritablePacket *q = p->uniqueify();
	click_chatter("checkpoint 1");
	if (!q) return 0;

	if (!(_src_set || _dst_set)) {
		click_chatter("checkpoint 2");
		memcpy(q->data() + _offset, &_address, 16);
	} else {
		if (_src_set) {
		click_chatter("checkpoint 3");

		} else { // _dst_set == true
		click_chatter("checkpoint 4");


		}
	}
	return q;


//    IP6Address ipa = (_use_address ? _address : IP6Address(p->anno_u16(DST_IP6_ANNO_OFFSET))); // p->anno_u16(DST_IP6_ANNO_OFFSET) werkt nog niet!
//    click_chatter("het ip adres is %s ", _address.unparse().c_str());
//    click_chatter("de offset is gelijk aan %i", _offset);
//    if ((ipa || _use_address) && ((uint32_t) _offset + 16 <= p->length())) {		// waarom ipa || _use_address  ?    _use_address is een boolean die niet meer gebruit wordt, niet? dus als je use_address = true hebt mag je altijd verder, zelfs als adres niet goed is................. maar dan die niet goed zijn???? waarom staat dit er eigenlijk bij.
//        click_chatter("we enteren de eerste lus");
//
//	if (WritablePacket *q = p->uniqueify()) {
//	    memcpy(q->data() + _offset, &ipa, 16);
//	    return q;
//	} else
//	    return 0;
//
//    } else if (_offset >= -24 && p->has_network_header()
//	       && p->ip_header_length() >= sizeof(click_ip6)) {
//        click_chatter("we enteren de tweede lus");
//	// special case: store IP address into IP header
//	// and update checksums incrementally
//	if (WritablePacket *q = p->uniqueify()) {
//	    uint16_t *x = reinterpret_cast<uint16_t *>(q->network_header() - _offset);
//	    uint32_t old_hw = (uint32_t) x[0] + x[1];
//	    old_hw += (old_hw >> 24);
//
//	    memcpy(x, &ipa, 16);
//
//	    uint32_t new_hw = (uint32_t) x[0] + x[1];
//	    new_hw += (new_hw >> 24);
//	    click_ip6 *iph = q->ip6_header();
//
//	    if (iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == IP_PROTO_TCP
//		&& q->transport_length() >= (int) sizeof(click_tcp))
//		click_update_in_cksum(&q->tcp_header()->th_sum, old_hw, new_hw);	// && IP_FIRSTFRAG(iph) viel weg, klopt dit dan nog???
//	    if (iph->ip6_ctlun.ip6_un1.ip6_un1_nxt == IP_PROTO_UDP
//		&& q->transport_length() >= (int) sizeof(click_udp)
//		&& q->udp_header()->uh_sum)
//		click_update_in_cksum(&q->udp_header()->uh_sum, old_hw, new_hw);	// && IP_FIRSTFRAG(iph) viel weg, klopt dit dan nog???
//
//	    return q;
//	} else
//	    return 0;
//
//    } else {
//        click_chatter("we enteren de laatste lus");
//	checked_output_push(1, p);  // output 1 is where we drop packets for which the OFFSET is out of range
//	return 0;
//    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StoreIP6Address)
ELEMENT_MT_SAFE(StoreIP6Address)
