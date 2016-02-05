/*
 * ip6filter2.{cc,hh} -- IPv6-packet filter with tcpdumplike syntax
 * Glenn Minne, based on code by Eddie Kohler
 *
 * Copyright (c) 2000-2007 Mazu Networks, Inc.
 * Copyright (c) 2010 Meraki, Inc.
 * Copyright (c) 2004-2011 Regents of the University of California
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
#include "ip6filter2.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/icmp.h>
#include <click/integers.hh>
#include <click/etheraddress.hh>
#include <click/nameinfo.hh>
#include <stack>
CLICK_DECLS

using std::stack;


// TODO this list is ordered alphabetically, wouldn't it be better if you order the list based on the specific TYPE????
// TODO these entries will be added to NameInfo's database system 





// hulp functie
// Gaat het type en het protocol vertalen naar een een leesbare string, en plakt daarachter het meegegeven woord.

// TODO why is word passed by reference?
static String
unparse_word(int typeNumber, int protocolNumber, const String &word)
{
    String typeName = IP6Filter::Primitive::unparse_type(0, typeNumber);
    String protocolName = IP6Filter::Primitive::unparse_transp_proto(protocolNumber);
    if (typeName)
	    typeName += " ";
    if (protocolName || (word && typeName)) // if word and tyeName were both unempty, we also add the extra space. TODO Why?
	    protocolName += " ";
    return typeName + protocolName + word;
}

// hulp functie lijkt mij
// deze geeft een getal terug, het teruggegeven getal bepaalt of er een match was of niet
// je kan onder andere -1 returnen als er geen match is, of ook wel -2 wat wil zeggen dat er ook geen match is maar dat we door alle mogelijkheden heen zijn moeten lopen

// geheugensteuntje: false wordt geconverteerd naar 0, true wordt geconverteerd naar 1


/** @Brief Helper function in which we query 5 databases in total to find for the given word. If we find in one of those databases the word, we return the associated number for that word. In the case the word occurs in multiple databases however, we give an error back. When the word wasn't found an error is also returned.    
    @param word The word where we want to find its official number for
    @param type The type we are hinting at? TODO
    @param proto The protocol we are hinting at? TODO
    @param data TODO why is this given?
    @param context The compound element that was given as a database query context TODO (I guess)
    @param errh The Click error handler.
*/



// lege constructor
IP6Filter::IP6Filter()          // TODO do we need to give _transp_proto a default value?
{
}

// lege destructor
IP6Filter::~IP6Filter()
{
}

//
// CONFIGURATION
//

// hiermee maak je een bepaalde primitive leeg
void
IP6Filter::Primitive::clear()           // TODO waarom wordt _proto niet gereset?
{
    _internalPrimitiveType = _srcdst = 0;
    _transp_proto = UNKNOWN;
    _data = 0;
    _internalOperatorType = OP_EQ;  // TODO the default operator seems to be OP_EQ, there does not seem to be something that indicates that an operator is abscent.
    _isInternalOperatorInNegatedForm = false;
}

// hiermee zet je het type vd primitive
// mogelijke types zijn: ... , ... , ... , ... , ...


// TODO wat betekenen de eerste 3 argumenten?

// TODO ik ben er niet helemaal zeker van maar dit lijkt niet alleen de mask te zetten, maar de data ook aan te passen zodat er op de delen waar het masker 0 geeft, er in de data ook effectief een 0 komt te staan.

// TODO what is full mask vs. provided mask?
int
IP6Filter::Primitive::set_mask(uint32_t full_mask, int shift, uint32_t provided_mask, ErrorHandler *errh)
{
    uint32_t data = _u.u;
    uint32_t this_mask = (provided_mask ? provided_mask : full_mask);       // TODO should maybe be renamed to mask. We are considering a mask. Normally this is the provided_mask , but in some cases when a provided_mask was not given, this is the boundary mask "full_mask", which states the size of the maximum mask. "full_mask" should maybe be renamed to max_mask.
// the actual mask should then be a subset of max_mask

    // TODO zie ook het bestand 'example_AND' in /home. Ik vermoed dat we er voor willen zorgen dat de data hetzelfde wordt als de data ge-&'nd met de mask. Dat betekent impliciet dat je op de delen waar het masker 0 had, ook 0 moet hebben staan.
    // this_mask must not be larger than the full_mask. The test below checks this condition.
    if ((this_mask & full_mask) != this_mask)      // TODO (nagaan of de uitspraak die hier volgt klopt) full_mask mag meer 1'en hebben dat this_mask denk ik, of mag 
                                                   // er ook volledig aan gelijk zijn eventueel. In alle andere gevallen is this_mask != full_mask denk ik en dan 
                                                   // hebben we een error.
	    return errh->error("%<%s%>: mask out of range, bound 0x%X", unparse_type().c_str(), full_mask);

    if (_internalOperatorType == OP_GT || _internalOperatorType == OP_LT) {
	    // Check for comparisons that are always true or false.
	    if ((_internalOperatorType == OP_LT && (data == 0 || data > this_mask)) || (_internalOperatorType == OP_GT && data >= this_mask)) {
	        bool will_be = (_internalOperatorType == OP_LT && data > this_mask ? !_isInternalOperatorInNegatedForm : _isInternalOperatorInNegatedForm);
	        errh->warning("relation %<%s %u%> is always %s (range 0-%u)", unparse_op().c_str(), data, (will_be ? "true" : "false"), this_mask);
	        _u.u = _mask.u = 0;
	        _isInternalOperatorInNegatedForm = !will_be;
	        _internalOperatorType = OP_EQ;
            return 0;
	    }

        // TODO => why are we doing what is described below?



    	// value < X == !(value > (X - 1)) 

        // Explanation of the above statement:
        // value < X == !(value > X) is easy
        // since we are using natural numbers, also value < X == !(value > (X - 1)). Because if if we only do -1, and we know that the numbers are all 1 apart from each each other, we can have at most that both numbers get equal, and equal is not great than (>).

      	if (_internalOperatorType == OP_LT) {
    	    _u.u--;         // contains a binary number, we subtract 1 from this binary number
    	    _isInternalOperatorInNegatedForm = !_isInternalOperatorInNegatedForm;
      	    _internalOperatorType = OP_GT;
	    }

	    _u.u = (_u.u << shift) | ((1 << shift) - 1);            // shift to the left and augment with 1s in stead of 0s
	    _mask.u = (this_mask << shift) | ((1 << shift) - 1);    // shift to the left and augment with 1s in stead of 0s
    	// Want (_u.u & _mask.u) == _u.u.
    	// So change 'tcp[0] & 5 > 2' into the equivalent 'tcp[0] & 5 > 1':
    	// find the highest bit in _u that is not set in _mask,
    	// and turn on all lower bits.
    	if ((_u.u & _mask.u) != _u.u) {
	        uint32_t full_mask_u = (full_mask << shift) | ((1 << shift) - 1);       // ((1 << shift) - 1) will give something that consists entirely of 1's
                                                                                    // actually we are shifting the full mask and adding 1's in stead of 0's to the right
	        uint32_t missing_bits = (_u.u & _mask.u) ^ (_u.u & full_mask_u);
	        uint32_t add_mask = 0xFFFFFFFFU >> ffs_msb(missing_bits);   // ffs_msb -> returns the index of the most significant bit set.
	        _u.u = (_u.u | add_mask) & _mask.u;
	    }
	    return 0;
    }

    if (data > full_mask)   // this means the data is out of range
	    return errh->error("%<%s%>: out of range, bound %u", unparse_type().c_str(), full_mask);

    _u.u = data << shift;               // as well the data , as the mask, are possibly shifted before being assigned to the Primitive-class member variables.
    _mask.u = this_mask << shift;
    return 0;
}

//
//  Here follows a series of unparse functions.
//

/** @Brief Returns the given internal primitive type number in written form, possibly preceded by a source/destination keyword.
    @param srcdst A source/destination keyword, which is an integer that indicates whether the internal primitive type was preceded by a source/destination keyword such as 'src' or 'src and dst'
    @param internalPrimitiveTypeNumber Each Primitive struct has a certain type associated with it. This type is given in a numerical form and this type is translated by this function to written form

*/
String
IP6Filter::Primitive::unparse_type(int srcdst, int internalPrimitiveTypeNumber)
{
  StringAccum sa;

  switch (srcdst) {
   case SOURCE: sa << "src "; break;
   case DEST: sa << "dst "; break;
   case SOURCE_OR_DEST: sa << "src or dst "; break;
   case SOURCE_AND_DEST: sa << "src and dst "; break;
  }

  switch (internalPrimitiveTypeNumber) {
   case TYPE_NONE: sa << "<none>"; break;
   case TYPE_HOST: sa << "ip host"; break;
   case TYPE_PROTO: sa << "proto"; break;
   case TYPE_ETHER: sa << "ether host"; break;
   case TYPE_IPFRAG: sa << "ip frag"; break;
   case TYPE_PORT: sa << "port"; break;
   case TYPE_TCPOPT: sa << "tcp opt"; break;
   case TYPE_NET: sa << "ip net"; break;
   case TYPE_IPUNFRAG: sa << "ip unfrag"; break;
   case TYPE_IPECT: sa << "ip ect"; break;
   case TYPE_IPCE: sa << "ip ce"; break;
   default:
    if (internalPrimitiveTypeNumber & TYPE_FIELD) {        // hiermee zult ge waarschijnlijk kunnen zien of u TYPE_FIElD gezet is, wat dan ook moge betekenen
      switch (internalPrimitiveTypeNumber) {               // hier volgen da al die typische veldjes die ge terugvint in een IPv4 adres, en dat zal moeten omgezet worden naar typische veldjes in een IPv6 adres
       case FIELD_IPLEN: sa << "ip len"; break;
       case FIELD_ID: sa << "ip id"; break;
       case FIELD_VERSION: sa << "ip vers"; break;
       case FIELD_HL: sa << "ip hl"; break;
       case FIELD_TOS: sa << "ip tos"; break;
       case FIELD_DSCP: sa << "ip dscp"; break;
       case FIELD_HLIM: sa << "ip hlim"; break;
       case FIELD_TCP_WIN: sa << "tcp win"; break;
       case FIELD_ICMP_TYPE: sa << "icmp type"; break;
       default:
	     if (internalPrimitiveTypeNumber & FIELD_PROTO_MASK)     // nog totaal onduidelijk wat dit wil zeggen, maar da zal nog duidelijk worden zeker     
	       sa << unparse_transp_proto((internalPrimitiveTypeNumber & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT);
	     else
	       sa << "ip";
	     sa << "[...]";
	     break;
      }
    } else
      sa << "<unknown type " << internalPrimitiveTypeNumber << ">";
    break;
  }

  return sa.take_string();
}
/** @brief Each Primitive struct has possibly a transport layer protocol number associated with it. This function translates this transport layer protocol number to written form.
@param transp_proto The numerical value that needs to be translated back to its corresponding written form.

*/
String
IP6Filter::Primitive::unparse_transp_proto(int transp_proto)
{
  switch (transp_proto) {
   case UNKNOWN: return "";
   case IP_PROTO_ICMP: return "icmp";       // IP_PROTO_ICMP is macro magic for '1', the IANA ICMP protocol number
   case IP_PROTO_IGMP: return "igmp";
   case IP_PROTO_IPIP: return "ipip";
   case IP_PROTO_TCP: return "tcp";
   case IP_PROTO_UDP: return "udp";
   case IP_PROTO_TCP_OR_UDP: return "tcpudp";
   case IP_PROTO_TRANSP: return "transp";
   default: return "ip proto " + String(transp_proto); // In this case the transport protocol did not get recognized. We return the written protocol number gently back then.
  }
}

/** @Brief Tells which sort of Primitive we have, and whether this Primitive was preceded by a source/dest keyword combination. The output is given in plain text.
@return The type and source/dest keyword combination, if present, given in plain text.
*/
String
IP6Filter::Primitive::unparse_type() const      // shortcut for unparse_type with two parameters.
{
  return unparse_type(_srcdst, _internalPrimitiveType);
}

/** @Brief Tells which sort of operator the Primitive has, and returns it in plain text.
@return The operator owned by the leading Primitive, given in plain text.

*/
String
IP6Filter::Primitive::unparse_op() const
{
  if (_internalOperatorType == OP_GT)
    return (_isInternalOperatorInNegatedForm ? "<=" : ">");
  else if (_internalOperatorType == OP_LT)
    return (_isInternalOperatorInNegatedForm ? ">=" : "<");
  else
    return (_isInternalOperatorInNegatedForm ? "!=" : "=");
}

// Here ends the series of unparse functions.

/** Negates is the negation is found simple. If it was not found simple, an assertion fails.

*/
void
IP6Filter::Primitive::simple_negate()
{
  assert(negation_is_simple());
  _isInternalOperatorInNegatedForm = !_isInternalOperatorInNegatedForm;
  if (_internalPrimitiveType == TYPE_PROTO && _mask.u == 0xFF)       // TODO why does the mask needs to be 0xFF ?
    _transp_proto = (_isInternalOperatorInNegatedForm ? UNKNOWN : _u.i);
}

/** Some sort of error function?

*/
int
IP6Filter::Primitive::type_error(ErrorHandler *errh, const char *msg) const
{
    return errh->error("%<%s%>: %s", unparse_type().c_str(), msg);
}

// TODO
// TODO     Deze functie kijkt heel wat zaken na op fouten.         (veronderstel ik)
// TODO
// TODO     Het getal nul returnen betekent dat alles in orde is.   (veronderstel ik)
// TODO








//
//  ***********************************************
//  *  header region               *  data region *
//  ***********************************************
//
// int header => Indicates a header type. There are 2 types 'e' and 'i'. 'e' is associated with a header region which only contains an Ethernet header. 'i' is associated with an header region which contains an Ethernet header, an IP header and possibly a transport header such as TCP or UDP.

// _data => Indicates the type of the data we need to check against. This data is also located in the header region in the picture above, so don't be confusd. This can be HOST, NET, ETHER, but can be as general as INTEGER. HOST is used when we check against an IP address, and the name stems from the fact that we use the 'host' keyword when checking against an IP adress.

// TODO wat is mask_dt, is dat een soort van 'overruling mask' die ge meegeeft om te gebruiken voor het geval dat ge de default mask die ze normaal gaan zetten niet goed vindt?

// TODO this function does more than setting alone, it passes prev_prim and mask by reference.

// TODO the primitive checks itself with this method. It also needs somehow a copy of the previous primitive that existed (as such a copy of that should have been made), and also a "header", a "mask_dt" and a "mask" which was given by reference. It would also be nice to know why prev_prim was given by reference. - So before we start we need to set the Primitive's values entirely.

// Seems to check whether the input was fillen in correctly. Thus that after for instance the port keyword, a number follows and not something crazy as an Ethernet address. Or an other example, for TYPE_NET things like a great than or smaller than operator are not allowed, only the equal than operator is allowed here.
int
IP6Filter::Primitive::check(const Primitive &prev_prim, int header, int mask_dt, const PrimitiveData &mask, ErrorHandler *errh) // TODO check doet precies toch nog iets? het zet precies masks! Merkwaardig!
{
    int old_srcdst = _srcdst;       // TODO pre requirement: the _srcdst variable MUST have been set first, before this function can be used.

    // if _internalPrimitiveType is erroneous, return -1 right away
    if (_internalPrimitiveType < 0)
	    return -1;

    // set _internalPrimitiveType if it was not specified
    // TODO shouldn't we throw some sort of an exception if a type was not given? => shouldn't the user always give a type?
    if (!_internalPrimitiveType) {       // that is, _internalPrimitiveType == 0.

        retry:                  // TODO pre requirement: the _data variable MUST have been set first, before this function can be used.
	    switch (_data) {            // hier zien we voor het eerst wat data allemaal kan inhouden, ook hier komen de keuzes weer uit een typisch enum lijstje met CONSTANTEN
	        
            //
            //  IPv6 Host address. Can be a source address, destination address or both.
            //
            case TYPE_HOST:
	        case TYPE_NET:

            //
            //  Ethernet Host address. Can be a source address, destination address or both.
            //
        	case TYPE_ETHER:

            //
            //  TCP Logic. Using the 'opt' keyword that needs to be followed by ack, fin, psh, rst, syn or urg.
            //
            //  TODO => wtf: why are we checking for the previous source dest stuff WHEN we have a TCPOPT construct? Weird :/
            //
	        case TYPE_TCPOPT:
	            _internalPrimitiveType = _data;
	            if (!_srcdst)   // if _srcdsr wasn't set (that is, it was == 0), then it will be set here.
		            _srcdst = prev_prim._srcdst;    // TODO Why do we choose it that it needs to choose the _srcdst of previous premitive, if none was given? Isn't that just weird? How does real wireshark handle this. Do they also handle it this way?
                                                    // TODO <obsolete comment> wat is het verschil tussen old_srcdst en prev_prim._srcdst ?
	            break;
    
            //
            //  Protocol following the IPv6 field
            //
	        case TYPE_PROTO:
	            _internalPrimitiveType = TYPE_PROTO;
	        break;

            //
            //  TCP & UDP Logic
            //
	        case TYPE_PORT:     // TODO what is the difference between TYPE_PROTO and TYPE_PORT? What is TYPE_PORT anyway?
	            _internalPrimitiveType = TYPE_PORT;
	            if (!_srcdst)       // if _srcdst wasn't set, then it will be set here.
		            _srcdst = prev_prim._srcdst;    // TODO Same comment as above. Why do we choose it that it needs to choose the _srcdst of the previous premitive, if none was given?
	            if (_transp_proto == UNKNOWN)   // if _transp_proto was still UNKOWN it will be set here.
		            _transp_proto = prev_prim._transp_proto;
	            break;

	        case TYPE_INT:
	            if (!(prev_prim._internalPrimitiveType & TYPE_FIELD) && prev_prim._internalPrimitiveType != TYPE_PROTO && prev_prim._internalPrimitiveType != TYPE_PORT)
		            return errh->error("specify header field or %<port%>");
	            _data = prev_prim._internalPrimitiveType;
	            goto retry;         // TODO in case of a TYPE_INT, it is not enough and we set our _data field to the previous _data field used and we RETRY.

	        case TYPE_NONE:
	            if (_transp_proto != UNKNOWN)       // if we have TYPE_NONE we will only set the _transp_proto when the _transp_proto is different from UNKOWN which makes sense.
		            _internalPrimitiveType = TYPE_PROTO;
	            else
		            return errh->error("partial directive");    // else error, partial directive is a word I must admit do not know.
	            break;

	        default:
	            if (_data & TYPE_FIELD) {   // if _data does not contain all 0's on TYPE_FIELD then set _internalPrimitiveType to _data
		            _internalPrimitiveType = _data;
		            if ((_internalPrimitiveType & FIELD_PROTO_MASK) && _transp_proto == UNKNOWN) // if _internalPrimitiveType does not contain all 0's on FIELD_PROTO_MASK then set _transp_proto to the given protocol (if _transp_proto wasn't still set.
		                _transp_proto = (_internalPrimitiveType & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT;
	            } else
		            return errh->error("unknown type %<%s%>", unparse_type(0, _data).c_str());  // type wasn't set yet, but we don't know what it should have been.
	            break;

        }
    }

    // header can modify type

    // the host keyword can mean two things: it can be followed by an Ethernet address or by an IP address. We determine here what it is, and if it is an Ethernet address we swap the internal type to TYPE_ETHER. See (*) below to see where it happens.
    if (header == 0 && _data == TYPE_ETHER)  // if header wasn't set and _data was TYPE_ETHER we set header to 'e'
	    header = 'e';
    else if (header == 0)                    // if header wasn't set and _data wasn't of TYPE_ETHER we set header to 'i'
	    header = 'i';
    if (header == 'e' && _internalPrimitiveType == TYPE_HOST)       // if header == 'e' and the TYPE was TYPE_HOST, we need to switch this into TYPE_ETHER
	    _internalPrimitiveType = TYPE_ETHER;                        // (*)

    // After the type was set, we execute the code associated with the type.
    switch (_internalPrimitiveType) {

        case TYPE_HOST:     // host <...>    . e.g. host 3ffe:1900:4545:3:200:f8ff:fe21:67cf <remaining statements>
	        if (header != 'i' || _data != TYPE_HOST)            // dan kijken we of wat achter het keyword volgt wel in het juiste formaat staat, achter het host keyword verwacht je een IP adres en dat zou je data dus van het type TYPE_HOST zijn, als dat niet het geval is, dan is er iets mis en hebben we een "address missing" fout.
	            return type_error(errh, "address missing");
	        if (_internalOperatorType != OP_EQ)                                   // only = is supported
	            goto operator_not_supported_error;
	        _ip6AddressMask = IP6Address::make_prefix(128);                                  // TODO: this needs to change cause I think it is now going to be about an IPv6 address; chances are very big that this rule can be left out since we are now working with an IP6Address field in our Primitive too. However it migt be possible and then we need to add an IP6Address field for the header too and this is to differentiate between the TYPE_HOST and TYPE_NET case. Actually I think this last thing is the truth.
	        goto set_host_mask;

        case TYPE_NET:      // TODO TYPE_HOST hierboven is al aangepast, maar TYPE_NET moet nog aanpassingen krijgen, we werken nu met de langere maskers
                            
                            // I am not sure how the TYPE_NET syntax actually looks like
	        if (header != 'i' || _data != TYPE_NET)
	            return type_error(errh, "address missing");
	        if (_internalOperatorType != OP_EQ)
	            goto operator_not_supported_error;
	        _internalPrimitiveType = TYPE_HOST;

            set_host_mask:

	        if (mask_dt && mask_dt != TYPE_INT && mask_dt != TYPE_HOST)
	            goto bad_mask;
	        else if (mask_dt)
	            _mask.u = mask.u;
	        break;

        case TYPE_ETHER:    // ether <...>
	        if (header != 'e' || _data != TYPE_ETHER)
	            return type_error(errh, "address missing");
	        if (_internalOperatorType != OP_EQ)
	            goto operator_not_supported_error;
	        memset(_mask.c, 0xFF, 6);
	        memset(_mask.c + 6, 0, 2);
	        if (mask_dt && mask_dt != TYPE_ETHER)
	            goto bad_mask;
	        else if (mask_dt)   // mask_dt is not zero
	            memcpy(_mask.c, mask.c, 6);   // void * memcpy ( void * destination, const void * source, size_t num )
	        break;

        case TYPE_PROTO:    // proto <...>
	        if (header != 'i')      // 'i' stands for IP
	            goto option_is_ip_only_error;       // if header is not an IP header, return an "ip only"-error
	        if (_data == TYPE_INT || _data == TYPE_PROTO) {
	            if (_transp_proto != UNKNOWN && _transp_proto != _u.i)
	            	return type_error(errh, "specified twice");
	            _data = TYPE_NONE;
	        } else
	            _u.i = _transp_proto;
	        _transp_proto = UNKNOWN;

	        if (_data != TYPE_NONE || _u.i == UNKNOWN)
	            goto value_missing;
            if (_u.i >= 256) {
	            if (_internalOperatorType != OP_EQ || mask_dt)
	                return errh->error("%<%s%>: operator or mask not supported", unparse_transp_proto(_u.i).c_str());
	            _mask.u = 0xFF;
            } else if (mask_dt && mask_dt != TYPE_INT)
	            goto bad_mask;
            else if (set_mask(0xFF, 0, mask_dt ? mask.u : 0, errh) < 0) // TODO does mask_dt stand for "mask determined"?
	            return -1;
            if (_internalOperatorType == OP_EQ && _mask.u == 0xFF && !_isInternalOperatorInNegatedForm) // set _transp_proto if allowed
	            _transp_proto = _u.i;
            break;

        case TYPE_PORT: // TYPE_PORT is only available if we at least have an IP header (only having an Ethernet header is insufficient)
	        if (header != 'i')  // 'i' stands for IP , but it indicates 'IP or higher level layers'  , while on the other hand 'e' really stands for 'Ethernet only'
	            goto option_is_ip_only_error;   // if header is not an IP header but is in stead an Ethernet header, return an "ip only"-error 
                                // => actually for this case we need to look at the transport header, but an indication of IP Header is our closest shot. An indication of 'e' would say we are specifically interested in the Ethernet header.
	        if (_data == TYPE_INT)
	            _data = TYPE_PORT;  // setting _data to TYPE_PORT maybe means that we have just met a TYPE_PORT argument. Firstly the _data field was set to TYPE_INT, but once we checked that out we substitute it with TYPE_PORT to indicate that the _data has been correctly read and interpreted.   // TODO checking out how true this statement is
	        if (_data != TYPE_PORT)         // TODO waarom niet werken met een else clause, het zal wel weer wat zijn, of bij de if een OR er bij zetten en dan 1 else clause, en dan zeggen van, als 't nog ni gezet is het zetten en anders is 't wel in orde
	            goto value_missing;     // it should have been TYPE_INT, if the data was of an other format, we have an error. As such we go to 'value_missing'.
	        if (_transp_proto == UNKNOWN)   // if _transp_proto was still unknown we set it to TCP or UDP
	            _transp_proto = IP_PROTO_TCP_OR_UDP;
	        else if (_transp_proto != IP_PROTO_TCP && _transp_proto != IP_PROTO_UDP && _transp_proto != IP_PROTO_TCP_OR_UDP && _transp_proto != IP_PROTO_DCCP) // In case the transport protocol was actually set we check whether it consists of a legal _transp_proto combination.
	            return errh->error("%<port%>: bad protocol %d", _transp_proto);
	        else if (mask_dt && mask_dt != TYPE_INT)
	            goto bad_mask;
	        if (set_mask(0xFFFF, 0, mask_dt ? mask.u : 0, errh) < 0)        // TODO mask_dt? mask.u : 0 zien we overal bij "set_mask", waarom is dat zo?
                                                                            // TODO de geleverde mask is wel overal gelijk, waarom is dat zo?
	            return -1;
	        break;

        case TYPE_TCPOPT:
	        if (header != 'i')
	            goto option_is_ip_only_error;
	        if (_data == TYPE_INT)
	            _data = TYPE_TCPOPT;
	        if (_data != TYPE_TCPOPT)
	            goto value_missing;
	        if (_transp_proto == UNKNOWN)
	            _transp_proto = IP_PROTO_TCP;
	        else if (_transp_proto != IP_PROTO_TCP)
	            return errh->error("%<tcp opt%>: bad protocol %d", _transp_proto);
	        if (_internalOperatorType != OP_EQ || _isInternalOperatorInNegatedForm || mask_dt)
	            return type_error(errh, "operator or mask not supported");
	        if (_u.i < 0 || _u.i > 255)
	            return errh->error("%<tcp opt%>: value %d out of range", _u.i);
	        _mask.i = _u.i;
	        break;

        case TYPE_IPECT:
	        if (header != 'i')
	            goto option_is_ip_only_error;
	        if (_data != TYPE_NONE && _data != TYPE_INT)    // only TYPE_NONE or TYPE_INT are allowed for the IP ECT type
	            goto value_missing;
	        if (_data == TYPE_NONE) {
	            _mask.u = IP_ECNMASK;
	            _u.u = 0;
	            _isInternalOperatorInNegatedForm = true;
	        } else if (mask_dt && mask_dt != TYPE_INT)
	            goto bad_mask;
	        if (set_mask(0x3, 0, mask_dt ? mask.u : 0, errh) < 0)       // 0x3 just indicates 2 bit, it is equal to 0b11
	            return -1;
	        _internalPrimitiveType = FIELD_TOS;
	        break;

        case TYPE_IPCE:
	        if (header != 'i')
	            goto option_is_ip_only_error;
	        if (_data != TYPE_NONE || mask_dt)
	            goto value_not_supported;
	        _mask.u = IP_ECNMASK;
	        _u.u = IP_ECN_CE;
	        _internalPrimitiveType = FIELD_TOS;
	        break;

        case TYPE_IPFRAG:
	        if (header != 'i')
	            goto option_is_ip_only_error;
	        if (_data != TYPE_NONE || mask_dt)
	            goto value_not_supported;
	        _mask.u = 1; // don't want mask to be 0
	        break;

        case TYPE_IPUNFRAG:
	        if (header != 'i')
	            goto option_is_ip_only_error;
	        if (_data != TYPE_NONE || mask_dt)
	            goto value_not_supported;
	        _isInternalOperatorInNegatedForm = true;
	        _mask.u = 1; // don't want mask to be 0
	        _internalPrimitiveType = TYPE_IPFRAG;
	        break;

        default:
	        if (_internalPrimitiveType & TYPE_FIELD) {   // _internalPrimitiveType should not contain all 0's on the TYPE_FIELD area.
	            if (header != 'i')
		            goto option_is_ip_only_error;       // only 'ip' is allowed in this part of the code; if not 'ip' go to ip_only-error to return an error.
	            if (_data != TYPE_INT && _data != _internalPrimitiveType)    // data is the type associated with the data supposingly.
		            goto value_missing;
	        else if (mask_dt && mask_dt != TYPE_INT && mask_dt != _internalPrimitiveType)    // mask_dt should not be 0, and should be either of TYPE_INT or of type _internalPrimitiveType.
		        goto bad_mask;
	        int nbits = ((_internalPrimitiveType & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;    // >> FIELD_LENGTH_SHIFT we do to place the bits in the rightmost positions so that we can read out the value of _internalPrimitiveType (I think). 
	        uint32_t xmask = (nbits == 32 ? 0xFFFFFFFFU : (1 << nbits) - 1);    // OK and here we create a correct mask based on the "nbits" that needs to be masked.
                                                                                // TODO => xmask seems to be some sort of more complicated way to determine the 4 byte mask.
	        if (set_mask(xmask, 0, mask_dt ? mask.u : 0, errh) < 0)     // setting the mask should not return any error, if it does, we return -1
		        return -1;
	        }
	        break;

        value_missing:
	        return type_error(errh, "value missing");
        bad_mask:
	        return type_error(errh, "bad mask");
        value_not_supported:
	        return type_error(errh, "value not supported");
        operator_not_supported_error:
	        return type_error(errh, "operator not supported");
        option_is_ip_only_error:
	        return type_error(errh, "ip only"); // an error to indicate that the option tried is only available for packets where an IP pointer is set (and as such, and IP header is assumed to be available
    }

    // fix _srcdst

    // for the host keyword and the port keyword, in the absence of a source/dest keyword, SOURCE_OR_DEST is assumed. (This is how Wireshark works)
    if (_internalPrimitiveType == TYPE_HOST || _internalPrimitiveType == TYPE_PORT || _internalPrimitiveType == TYPE_ETHER) {
	    if (_srcdst == 0)
	        _srcdst = SOURCE_OR_DEST;    // SOURCE_OR_DEST : look at both the source and the destination 'host', 'port' or 'ether' address
    } else if (old_srcdst)
	    errh->warning("%<%s%>: %<src%> or %<dst%> ignored", unparse_type().c_str());

    return 0;       // return 0 is good news, all tests/checks on the data succeeded.
}

// This function handles transport layer protocols (such as TCP and UDP).
static void
add_exprs_for_proto(int32_t proto, int32_t mask, Classification::Wordwise::Program &program, Vector<int> &tree)
{
    if (mask == 0xFF && proto == IP_PROTO_TCP_OR_UDP) {         // 0xFF = 255 in decimaal
	    program.start_subtree(tree);
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(IP_PROTO_TCP << 16), htonl(0x00FF0000));  // = htonl(16711680) ; this is the TCP rule.
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(IP_PROTO_UDP << 16), htonl(0x00FF0000));  // = htonl(16711680) ; this is the UDP rule.
	    program.finish_subtree(tree, Classification::c_or);
    } else if (mask == 0xFF && proto >= 256)                    // 0xFF = 255 in decimaal
	    /* nada */;
    else
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(proto << 16), htonl(mask << 16)); // proto << 16 and mask << 16, is used to bring the proto and mask values in the correct place into the packet.
}

void
IP6Filter::Primitive::add_comparison_exprs(Classification::Wordwise::Program &program, Vector<int> &tree, int offset, int shift, bool swapped, bool op_negate) const
{
  assert(_internalOperatorType == IP6Filter::OP_EQ || _internalOperatorType == IP6Filter::OP_GT);   // enkel deze twee expressies zien er mij vergelijkende/comparisson expressies uit, de andere _internalOperatorType types zullen geen comparison types zijn wrs
// opmerking: _internalOperatorType wordt wel niet meegegeven als argument hier, het lijkt mij een member te zijn van de structure Primite!!

  uint32_t mask = _mask.u;          // TODO  dit is langer denk ik bij IPv6 !
  uint32_t u = _u.u & mask;         // we &'en de originele data met de mask
                                    // TODO de mask meegeven als een parameter lijkt mij logischer en ik zie niet echt waarom een mask in een primitive moet steken

                                    // TODO  Waarom wordt de mask niet meegegeven als een argument van deze functie??
  if (swapped) {                    // mostly this will not be the case I suppose.
    mask = ntohl(mask);
    u = ntohl(u);
  }

  // (a) OP_EQ part , for comparing two espressions with one another

  // TODO dit moet je doen bij het checken op gelijkheid (of ongelijkheid bij een op_negate) 
  // -> de waarde in u pakket moet gelijk zijn aan die opgegeven hier om een match te hebben
  if (_internalOperatorType == IP6Filter::OP_EQ) {
    program.add_insn(tree, offset, htonl(u << shift), htonl(mask << shift));          // Waarom hebben we 'u' dan ge-&'nd met mask als je hier ook uw 'u' en uw 'mask' moet meegeven? :/
    if (_isInternalOperatorInNegatedForm && op_negate)           // Why are we asking for some sort of a double check here with op_negate, if the _isInternalOperatorInNegatedForm was set, do we not always then need to revert the tree?
      program.negate_subtree(tree, true);
    return;
  }

  // (b) for comparing non equality expressions (like smaller than/greater than)

  // TODO dit moet je doen bij het checken op groter dan (of kleiner of gelijk aan bij een op_negate) 
  // -> de waarde in u pakket moet groter zijn dan deze waarde om een matcht te hebben

  // To implement a greater-than test for "input&MASK > U":
  // Check the top bit of U&MASK.
  // If the top bit is 0, then:
  //    Find TOPMASK, the top bits of MASK s.t. U&TOPMASK == 0.
  //    If "input&TOPMASK == 0", continue testing with lower bits of
  //    U and MASK; combine with OR.
  //    Otherwise, succeed.
  // If the top bit is 1, then:
  //    Find TOPMASK, the top bits of MASK s.t. (U+1)&TOPMASK == TOPMASK.
  //    If "input&TOPMASK == TOPMASK", continue testing with lower bits of
  //    U and MASK; combine with AND.
  //    Otherwise, fail.
  // Stop testing when U >= MASK.

  int high_bit_record = 0;
  int count = 0;

  while (u < mask) {
    int high_bit = (u > (mask >> 1));
    int first_different_bit = 33 - ffs_msb(high_bit ? ~(u+1) & mask : u);
    uint32_t upper_mask;
    if (first_different_bit == 33)
      upper_mask = mask;
    else
      upper_mask = mask & ~((1 << first_different_bit) - 1);
    uint32_t upper_u = (high_bit ? 0xFFFFFFFF & upper_mask : 0);    // 0xFFFFFFFF = 4294967295 in het decimaal

    program.start_subtree(tree);
    program.add_insn(tree, offset, htonl(upper_u << shift), htonl(upper_mask << shift));
    if (!high_bit)
      program.negate_subtree(tree, true);
    high_bit_record = (high_bit_record << 1) | high_bit;
    count++;

    mask &= ~upper_mask;
    u &= mask;
  }

  while (count > 0) {
    program.finish_subtree(tree, (high_bit_record & 1 ? Classification::c_and : Classification::c_or));
    high_bit_record >>= 1;
    count--;
  }

  if (_isInternalOperatorInNegatedForm && op_negate)
    program.negate_subtree(tree, true);
}

// here the main code will be generated for the 'tests' (see grammar above parse_expr_iterative(...) for more details about what a test means)
void
IP6Filter::Primitive::compile(Classification::Wordwise::Program &program, Vector<int> &tree) const
{
  click_chatter("we enter P6Filter::Primitive::compile(...)");
  program.start_subtree(tree);            // each Primitive gets its own tree I suppose.

  // handle transport protocol uniformly
  if (_transp_proto != UNKNOWN)             // TODO add information. If a transport protocol was given, we'll create the transport protocol instructions right here.
                                            // TODO add_exprs_for_proto seems to be only used 1 time. It might be better to just add this information here inline then.
    add_exprs_for_proto(_transp_proto, 0xFF, program, tree);  // 0xFF = 255 in het decimaal

  // enforce first fragment: fragmentation offset == 0
  if (_internalPrimitiveType == TYPE_PORT || _internalPrimitiveType == TYPE_TCPOPT || ((_internalPrimitiveType & TYPE_FIELD) && (_internalPrimitiveType & FIELD_PROTO_MASK))) // type is either TYPE_PORT, TYPE_TCPOPT or some random type that has the TYPE_FIELD and FIELD_PROTO_MASK field set.
    program.add_insn(tree, offset_net + 4, 0, htonl(0x00001FFF)); // htonl(0x00001FFF)    = htonl(8191) in het decimaal


  // handle other types
  switch (_internalPrimitiveType) 
  {
    case TYPE_HOST:       // For each of our types, we start a subtree.
    {
      const uint32_t* ip6AddressArray;
      ip6AddressArray = _ip6Address.data32();
      program.start_subtree(tree);
      // With SOURCE_AND_DEST and SOURCE_OR_DEST we need to add both the source IP address and destintation IP address to the tree (so we need both the first add_comparison_exprs as the second one) , with SOURCE we only need to add the source IP address to the tree (so we only add the first add_comparison_exprs statement), and with DEST we only need to add the destination IP address to the tree (so we only add the second add_comparison_exprs statement).
      // In the case of SOURCE_AND_DEST and SOURCE_OR_DEST we choose the approriate combine option (namely Classification::c_or OR Classification::c_and) and in the case of SOURCE and DEST we don't really care because we have only one node, so AND'ing or OR'ing here does exactly the same.


      // TODO rol van SOURCE_OR_DEST onderzoeken in deze context; deel hieronder dat er nu dubbel in staat nog wissen; laatste deel op _isInternalOperatorInNegatedForm laten staan (en dus niet wissen)
      if (_srcdst == SOURCE) {
            program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);      // offset_net +8 to +20 contain the source address in an IPv6 packet
            program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);

            program.finish_subtree(tree, Classification::c_and);
      } else if (_srcdst == DEST) {
            program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);      // offset_net +24 to +36 contain the destination address in an IPv6 packet
            program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);

            program.finish_subtree(tree, Classification::c_and); 
      } else if (_srcdst == SOURCE_AND_DEST) {
            program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);     
            program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);

            program.finish_subtree(tree, Classification::c_and); 
      } else if (_srcdst == SOURCE_OR_DEST) {
            program.start_subtree(tree);
            program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);
            program.finish_subtree(tree, Classification::c_and);

            program.start_subtree(tree);
            program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
            program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);
            program.finish_subtree(tree, Classification::c_and);

            program.finish_subtree(tree, Classification::c_or);
      } else {
            // Throw an error
      }   

      if (_srcdst == SOURCE || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST) {
            // TODO nakijken wat we hier moeten doen , nog niet in orde


            // TODO we doen momenteel enkel operator IP6Filter::OP_EQ , kleiner dan of grote dan is complexer als bij een adres dat maar 32 bits lang is.
            // TODO ik denk dat nu de truuk gaat zijn om eerst de meest significante bits te vergelijken, als deze geen uitsluiten geven gaan we naar de 2de reeks bit, als die nog geen uitsluitsel geven naa de 3de reeks bits, en als die nog geen uitsluitsel geven naar de 4de reeks bits.
 //           const uint32_t* ip6AddressArray = _ip6Address.data32();    // we get our IP address now as an array of 4 32-bit values, which is what we need for our instruction language wich works with 32-bit words. 

//            IP6Address tempMask = IP6Address::make_prefix(128);             // TODO dit is tijdelijk; een prefix van 128 is gelijk aan ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff



            // Is dit juist?


            program.finish_subtree(tree, Classification::c_and);      // hopelijk is dit juist

	    //    add_comparison_exprs(p, tree, offset_net + 12, 0, true, false);     // deze regel moet er nog tussen uit
       }       
      if (_srcdst == DEST || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST)
	    add_comparison_exprs(program, tree, offset_net + 16, 0, true, false);
  finish_srcdst:
 //     program.finish_subtree(tree, (_srcdst == SOURCE_OR_DEST ? Classification::c_or : Classification::c_and));
      if (_isInternalOperatorInNegatedForm)      // if the statement is preceeded with 'not' or '!' we need to negate the subtree
	    program.negate_subtree(tree, true);
      break;
    }

  case TYPE_ETHER: {
      program.start_subtree(tree);
      Primitive copy(*this);
      if (_srcdst == SOURCE || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST) {
        program.start_subtree(tree);

	    memcpy(copy._u.c, _u.c, 4);
	    memcpy(copy._mask.c, _mask.c, 4);
	    copy.add_comparison_exprs(program, tree, offset_mac + 8, 0, true, false);
	    copy._u.u = copy._mask.u = 0;
	    memcpy(copy._u.c, _u.c + 4, 2);
	    memcpy(copy._mask.c, _mask.c + 4, 2);
	    copy.add_comparison_exprs(program, tree, offset_mac + 12, 0, true, false);

        program.finish_subtree(tree, Classification::c_and);
      }
      if (_srcdst == DEST || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST) {
        program.start_subtree(tree);

	    copy._u.u = copy._mask.u = 0;
	    memcpy(copy._u.c + 2, _u.c, 2);
	    memcpy(copy._mask.c + 2, _mask.c, 2);
	    copy.add_comparison_exprs(program, tree, offset_mac, 0, true, false);
	    memcpy(copy._u.c, _u.c + 2, 4);
	    memcpy(copy._mask.c, _mask.c + 2, 4);
	    copy.add_comparison_exprs(program, tree, offset_mac + 4, 0, true, false);

        program.finish_subtree(tree, Classification::c_and);
      }
      goto finish_srcdst;
  }

  case TYPE_PROTO:
  {
      if (_transp_proto < 256)
	    add_comparison_exprs(program, tree, offset_net + 8, 16, false, true);
      break;
  }

  case TYPE_IPFRAG:
  {
      program.add_insn(tree, offset_net + 4, 0, htonl(0x00003FFF));
      if (!_isInternalOperatorInNegatedForm)
	    program.negate_subtree(tree, true);
      break;
  }

  case TYPE_PORT:
  {
      program.start_subtree(tree);
      if (_srcdst == SOURCE || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST)
	    add_comparison_exprs(program, tree, offset_transp, 16, false, false);
      if (_srcdst == DEST || _srcdst == SOURCE_AND_DEST || _srcdst == SOURCE_OR_DEST)
	    add_comparison_exprs(program, tree, offset_transp, 0, false, false);
      goto finish_srcdst;
  }
 
  case TYPE_TCPOPT:
  {
      program.add_insn(tree, offset_transp + 12, htonl(_u.u << 16), htonl(_mask.u << 16));
      break;
  }

  default:
  {   // if internal primitive type was not set to a "normal" number, it needs to be checken against some fields, like the "TYPE-FIELD",
      // the "FIELD_OFFSET_MASK" field and the "FIELD_LENGTH_MASK" field.
      if (_internalPrimitiveType & TYPE_FIELD) {
	    int offset = (_internalPrimitiveType & FIELD_OFFSET_MASK) >> FIELD_OFFSET_SHIFT;
	    int length = ((_internalPrimitiveType & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;
	    int word_offset = (offset >> 3) & ~3, bit_offset = offset & 0x1F;
	    int base_offset = (_internalPrimitiveType & FIELD_PROTO_MASK ? offset_transp : offset_net); // we choose between the transport layer offset OR the "normal" network layer offset
	    add_comparison_exprs(program, tree, base_offset + word_offset, 32 - (bit_offset + length), false, true); // we start with the base_offset and count the 
                                                                                                                 // word_offset with that value.

                                                                                                                    // 32 is total number of bits
                                                                                                                    // - (bit_offset + how long the bit offset is)
                                                                                                                  
      } else
	    assert(0);
      break;
  }
 }

  program.finish_subtree(tree);
}

// TODO hoe werkt dit? in wat voor units wordt u tekst opgedeeld? => documentatie ontbreekt!
static void
separate_text(const String &text, Vector<String> &words)
{
  const char* s = text.data();
  int len = text.length();
  int pos = 0;
  while (pos < len) {
    while (pos < len && isspace((unsigned char) s[pos]))        // I think they want to skip  blanks here
      pos++;
    switch (s[pos]) {           // now we something different from a blank, but what do we have?

     case '&': case '|':
      if (pos < len - 1 && s[pos+1] == s[pos])
	goto two_char;                              // we have 1 or 2 times an & or a | , as such we need to go to one_char or two_char respectively
      goto one_char;

     case '<': case '>': case '!': case '=':
      if (pos < len - 1 && s[pos+1] == '=')     // we have 1 or 2 times an = , as such we need to go to one_char or two_char respectively    
	goto two_char;
      goto one_char;

     case '(': case ')': case '[': case ']': case ',': case ';':        // parenteces are always one char, as such we need to move always to one_char
     case '?':
     one_char:
      words.push_back(text.substring(pos, 1));
      pos++;
      break;

     two_char:
      words.push_back(text.substring(pos, 2));
      pos += 2;
      break;

     default: {                                 // in the default case we face a piece of text and we need to push the whole text back
	    int first = pos;
	    while (pos < len && (isalnum((unsigned char) s[pos]) || s[pos] == '-' || s[pos] == '.' || s[pos] == '/' || s[pos] == '@' || s[pos] == '_' || s[pos] == ':')) // isalnum is a c function in the <cctype> library which checks if a character is alphanumeric.

// int isalnum (int c) checks whether c is either a decimal digit or an uppercase or lowercase letter.
// the result is true if either isalpha or isdigit would also return true.

// so as long as we are still facing an alphanumeric character or one of the exceptional characters like -,.,/,@,_ and : we need to keep reading and we need to stop as soon as we see a special character OR if we are at the end of the to be parsed string.
	        pos++;
	        if (pos == first)
	            pos++;
	        words.push_back(text.substring(first, pos - first));
	        break;
        }

    }
  }
}

/* A grammar for the "Wireshark language consisting of Wireshark primitives and conjugates" given in an EBNF-like format.
 * -> term is more or less an andexpr you could say.
 *
 * expr ::= orexpr
 *	|   orexpr ? expr : expr
 * orexpr ::= orexpr || orexpr
 *	|   orexpr or orexpr
 *	|   term
 * term ::= term && term
 *	|   term and term
 *	|   term factor			// juxtaposition = and
 *	|   term
 *  |
 * factor ::= ! factor
 *	|   ( expr )
 *	|   primitive
 * primitive ::= true
 *	|   false
 *	|   qualifiers data
 *	|   qualifiers relationoperator data
 */

// TODO
// TODO         deze functie wordt veel gecalled gedurende de configuratiefase; het wordt gebruikt bij het opbouwen van zprog  (zprog wordt dus gemaakt tijdens de configuratie fase maar dat wisten we wrs al!)
// TODO         Maar: wat doet ze net? Gaat ze het programma helemaal omzetten in zprog taal?? Let's watch & see!!
// TODO 


// TODO position might be currentPositionInWordsList
int
IP6Filter::Parser::parse_expr_iterative(int position)        // Remark: This position variable given as a parameter is actually used and updated along the way in this function. However, since it is not passed by reference it will not change upon returning.

// TODO seems like we work with a pushdown automata here => we use the version that accepts when emptying the parseStack (cfr. Introduction to automata theory, languages and computation by Hopcroft, Motwani and Ullman).

// zo'n pushdown automaat is in essentie een niet-deterministische eindige automaat met epsilon transities toegestaan en 1 bijkomstige eigenschap: een parseStack waarop het een string van "stack symbolen" kan opslaan.
{
    stack<ParseState> parseStack;
    parseStack.push(ParseState(s_expr0));

    while (parseStack.size()) {
	    ParseState &parseState = parseStack.pop();
	    int newStateNumber = -1; // -1 means epsilon in the 'Introduction to automata theory' book

    	switch (parseState.stateNumber) { // tells in which state we are
            case s_expr0:                           // TODO enkel bij s_expr0 start men en subtree, bij de overige twee s_expr's niet
	            _program.start_subtree(_tree);      // whenever you start a subtree this means that you are setting up a new &&, ? or || construct or the like              
	            parseState.stateNumber = s_expr1;                 // TODO dit is de volgende staat die je moet uitproberen als het niet matcht denk ik, bij 0 kan 't nooit matchen denk ik
	            newStateNumber = s_orexpr0;     // this on the other hand is the new symbol that needs to be pushed on the stack (and has nothing to do with the state we are in) ; if the stack gets empty we need are finished.
	            break;
        	case s_expr1:
	            if (position >= _words.size() || _words[position] != "?")
		            goto finish_expr;               // TODO mss is dit als je merkt dat het blijkbaar geen expressie met een ? is, dus wandel je verder en probeer je iets anders, je finisht dit gedeelte en wandelt dus naar de vlgende mogelijkheid, een s_orexpr0 :p
	            ++position;      // Attention: the position variable (defaulted at 1) gets increased here.
	            parseState.stateNumber = s_expr2;                 // TODO dit is de volgende staat die je moet uitproberen als het niet matcht denk ik
	            newStateNumber = s_expr0;
	            break;
	        case s_expr2:
	            if (position == parseState.lastPosition || position >= _words.size() || _words[position] != ":") {
		            _errh->error("missing %<:%> in ternary expression");
		            goto finish_expr;
	            }
	            ++position;      // Attention: the position variable (defaulted at 1) gets increased here.
	            parseState.stateNumber = s_expr1;                 // TODO is dit wel de volgende staat die je moet proberen als 't niet matcht?? hmmn :o
	            newStateNumber = s_orexpr0;
	            break;

	            finish_expr:
	                _program.finish_subtree(_tree, Classification::c_ternary);         // TODO enkel bij s_expr2 beindigt men de subtree, bij de overige twee s_expr's niet
	                break;                                                          // TODO dit is ternary want er staat 'orexpr ? expr : expr'

	        case s_orexpr0:                         // TODO enkel bij s_orexpr0 start men een subtree, bij de andere s_orexpr niet
	            _program.start_subtree(_tree);          // Let's start an OR subtree
	            parseState.stateNumber = s_orexpr1;
	            newStateNumber = s_term0;
	            break;
	        case s_orexpr1:
	            if (position >= _words.size() || (_words[position] != "or" && _words[position] != "||"))
		            goto finish_orexpr;
	            ++position;
	            newStateNumber = s_term0;
	            break;

	            finish_orexpr:
	                _program.finish_subtree(_tree, Classification::c_or);          // TODO enkel bij s_orexpr1 beeindigt men de subtree, bij de andere s_orexpr niet
	                break;

	        case s_term0:
	            _program.start_subtree(_tree);          // Let's start an AND subtree
	            parseState.stateNumber = s_term1;
	            newStateNumber = s_factor0;
	            break;
	        case s_term1:
	        case s_term2:
	            if (position == parseState.lastPosition) {  // TODO if position == parseState.lastPosition we stayed at the same word position; how can this happen?
		            if (parseState.stateNumber == s_term1)
		                _errh->error("missing expression");
		            goto finish_term;
	            }
	            if (position < _words.size() && (_words[position] == "and" || _words[position] == "&&")) {
		            parseState.stateNumber = s_term1;
		            ++position;
	            } else
		            parseState.stateNumber = s_term2;
	            newStateNumber = s_factor0;
	            break;

	            finish_term:
	                _program.finish_subtree(_tree);    // The default value is Classification::c_and I believe.
	            break;

	        case s_factor0:
	        case s_factor0_neg:
	            if (position < _words.size() && (_words[position] == "not" || _words[position] == "!")) {
		            parseState.stateNumber += (s_factor1 - s_factor0);
	    	        newStateNumber = (parseState.stateNumber == s_factor1 ? s_factor0_neg : s_factor0); // TODO if we where in s_factor1 we go to s_factor0_neg, if we ere in s_factor1_neg we go to s_factor_0 I suppose
	    	        ++position;
	            } else if (position < _words.size() && _words[position] == "(") {
		            parseState.stateNumber += (s_factor2 - s_factor0);
		            newStateNumber = s_expr0;
		            ++position;
	            } else
		            position = parse_primitive(position, parseState.stateNumber == s_factor0_neg);// die test in het tweede argument gebruiken we om te zien of we het resultaat moeten negaten
	            break;                                                      // => we zitten hier bij een test, een test is volgens de grammatica hierboven: false, quals data of quals relop data
	        case s_factor1:
	        case s_factor1_neg:
	            if (position == parseState.lastPosition)
		            _errh->error("missing expression after %<%s%>", _words[position - 1].c_str());
	            break;
	        case s_factor2:
	        case s_factor2_neg:
	            if (position == parseState.lastPosition)
		            _errh->error("missing expression after %<(%>");
	            if (position < _words.size() && _words[position] == ")")
		            ++position;
	            else if (position != parseState.lastPosition)
		            _errh->error("missing %<)%>");
	            if (parseState.stateNumber == s_factor2_neg)
		            _program.negate_subtree(_tree);
	            break;
	        }

	    if (newStateNumber >= 0) {       // if the encountered state is positive, we need to push back
	        parseState.lastPosition = position;
	        parseStack.push(ParseState(newStateNumber));
	    } else                      // if the encountered state is negative, we need to pop
	        parseStack.pop();
    }

    return position;
}

// TODO I suppose they mean to parse square brackets, however no documentation was added to this part of the code.
static int
parse_brackets(IP6Filter::Primitive& prim, const Vector<String>& words, int pos, ErrorHandler* errh)
{
  int first_pos = pos + 1; // Don't look at first_pos. This is only used in case of an error.
  String combination;
  for (pos++; pos < words.size() && words[pos] != "]"; pos++)
    combination += words[pos];
  if (pos >= words.size()) {
    errh->error("missing %<]%>");       // We didn't encounter the closing bracket. This leads to an error.
    return first_pos;
  }
  pos++;

  // parse 'combination'
  int fieldpos, len = 1;
  const char* colon = find(combination.begin(), combination.end(), ':');        // a colon is something like ':'
  const char* comma = find(combination.begin(), combination.end(), ',');        // a comma is something like ','
  if (colon < combination.end() - 1) {
    if (cp_integer(combination.begin(), colon, 0, &fieldpos) == colon
	&& cp_integer(colon + 1, combination.end(), 0, &len) == combination.end())
      goto non_syntax_error;
  } else if (comma < combination.end() - 1) {
    int pos2;
    if (cp_integer(combination.begin(), comma, 0, &fieldpos) == comma
	&& cp_integer(comma + 1, combination.end(), 0, &pos2) == combination.end()) {
      len = pos2 - fieldpos + 1;
      goto non_syntax_error;
    }
  } else if (IntArg().parse(combination, fieldpos))
    goto non_syntax_error;
  errh->error("syntax error after %<[%>, expected %<[POS]%> or %<[POS:LEN]%>");
  return pos;

 non_syntax_error:
  int multiplier = 8;
  fieldpos *= multiplier, len *= multiplier;
  if (len < 1 || len > 32)
    errh->error("LEN in %<[POS:LEN]%> out of range, should be between 1 and 4");
  else if ((fieldpos & ~31) != ((fieldpos + len - 1) & ~31))
      errh->error("field [%d:%d] does not fit in a single word", fieldpos/multiplier, len/multiplier);
  else {
    int transp = prim._transp_proto;
    if (transp == IP6Filter::UNKNOWN)
      transp = 0;
    prim.set_type(IP6Filter::TYPE_FIELD
		  | (transp << IP6Filter::FIELD_PROTO_SHIFT)
		  | (fieldpos << IP6Filter::FIELD_OFFSET_SHIFT)
		  | ((len - 1) << IP6Filter::FIELD_LENGTH_SHIFT), errh);    // TODO wth is dit?
  }
  return pos;
}

// parse 'test' on encountering it.
int
IP6Filter::Parser::parse_primitive(int position, bool negatedSignSeen)    // parse het test gedeelte uit de grammatica
{
    // error handling
    if (position >= _words.size())
	    return position;    /* out of range */
	if (_words[position] == ")" || _words[position] == "||" || _words[position] == "?" || _words[position] == ":" || _words[position] == "or" )
	    return position;    /* non-acceptable first word */
	  
	// start of parsing
	if (_words[position] == "true") {
	    _program.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (negatedSignSeen)
	        _program.negate_subtree(_tree);
	    return position + 1;    /* go further in parse_expr_iterative() with the next position */
	}
	if (_words[position] == "false") {
	    _program.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (!negatedSignSeen)               
	        _program.negate_subtree(_tree);
	    return position + 1;    /* go further in parse_expr_iterative() with the next position */
	}
	for (int i = 0; i < _words.size; i++) {
	    String currentWord = _words[i];
	    if (currentWord == "vers") {
	        
	    } else if (currentWord == "dscp") {
	    
	    } else if (currentWord == "ce") {
	    
	    } else if (currentWord == "ect") {
	    
	    } else if (currentWord == "flow") {
	    
	    } else if (currentWord == "plen") {
	    
	    } else if (currentWord == "nxt") {
	    
	    } else if (currentWord == "hlim") {
	    
	    }
	}
	    
	

    // hard case

    // expect quals [relop] data
    // (relop is an abbreviation for relation operator, this is something as ==, !=, >=, >, <= or <).

    int startPosition = position;
    Primitive primitive;
    int header = 0;         // TODO we start with header = 0 , can it be given a value later on still in this function, that is: before we enter the 'check' function

    // collect qualifiers

    // hier worden de duizenden qualifiers verzameld en allemaal gezet in de primitive
    // de volgorde waarin die voorkomen lijkt hen niet te boeien, merkwaardig! Niet per se slecht, maar wel merkwaardig!

    // TODO waar wordt de data verzameld die normaal achter de qualifier moet komen?

    for (; position < _words.size(); position++) {  // for each word, do
	    String word = _words[position];
	    uint32_t wdata;
	    int wordType = lookup(word, 0, UNKNOWN, wdata, _context, 0);            // TODO waarom ze naar een word type moeten zoeken zie ik niet echt in, lijkt mij misschien een nutteloze operatie, je kan toch gewoon hard coded werken zoals ze doen bij src, gewoon   "else if (wd == "src")", ... enz.
                                                                        // of kijken ze hier naar u header pointers? om bijvoorbeeld te weten wat bepaalde dingen in bepaalde contexten willen zeggen? 't zou mij straf lijken.

	    if (wordType >= 0 && wordType == TYPE_TYPE) {
	        primitive.set_type(wdata, _errh);
	        if ((wdata & TYPE_FIELD) && (wdata & FIELD_PROTO_MASK))
		        primitive.set_transp_proto((wdata & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT, _errh);

	    } else if (wordType >= 0 && wordType == TYPE_PROTO)
	        primitive.set_transp_proto(wdata, _errh);

	    else if (wordType != -1)
	        break;

	    else if (word == "src") {
	        if (position < _words.size() - 2 && (_words[position+2] == "dst" || _words[position+2] == "dest")) {
		        if (_words[position+1] == "and" || _words[position+1] == "&&") {
		            primitive.set_srcdst(SOURCE_AND_DEST, _errh);
		            position += 2;       // move to the next word ; we have already encountered 'src and'
		        } else if (_words[position+1] == "or" || _words[position+1] == "||") {
		            primitive.set_srcdst(SOURCE_OR_DEST, _errh);
		            position += 2;       // move to the next word ; we have already encountered 'src or'
		        } else
		            primitive.set_srcdst(SOURCE, _errh);
	        } else
		        primitive.set_srcdst(SOURCE, _errh);
	    } else if (word == "dst" || word == "dest")     // TODO does this mean that 'dst or src' is not an allowable combination? it seems like that, you need to start your sentence with 'src or' it seems, or am I getting in wrong?
	        primitive.set_srcdst(DEST, _errh);     // maybe they prevent from resetting this ........ (when it's already set.........)

	    else if (word == "ip" || word == "ether") {
	        if (header)     // if the header already exists and is as such different from 0, we break
		        break;
	        header = word[0]; // otherwise our header will become our first word

	    } else if (word == "not" || word == "!")
	        negated = !negated;         // whenever you see the not keyword, swap the negated sign. Negations cancel each other out.

	    else
	        break;
    }

    // prev_prim is not relevant if there were any qualifiers
    if (position != startPosition)
	    _prev_prim.clear();         // and then we need to clear _prev_prim also
    if (_prev_prim._data == TYPE_ETHER)
	    header = 'e';

    // optional [] syntax
    // This optional [] syntax is used for
    // 'ip[POS:LEN] VALUE' and also for 'transp[POS:LEN] VALUE' constructs    
    String word = (position >= _words.size() - 1 ? String() : _words[position]);
    if (word == "[" && position > startPosition && primitive._internalPrimitiveType == TYPE_NONE) {
	    position = parse_brackets(primitive, _words, position, _errh);
	    word = (position >= _words.size() - 1 ? String() : _words[position]);
    }

    // optional bitmask

    // TODO what's the optional bit mask?
    int mask_dt = 0;
    PrimitiveData provided_mask;
    if (word == "&" && position < _words.size() - 1) {     // TODO how does the & word actually work like here, I think I didn't found an example of these sort of & syntax in the documentation.
	    if (IntArg().parse(_words[position + 1], provided_mask.u)) {
	        mask_dt = TYPE_INT;                                                 // TODO here we say something is of type TYPE_INT !!
	        position += 2;
	    } else if (header != 'e' && IPAddressArg().parse(_words[position + 1], provided_mask.ip4, _context)) { // TODO make IPv6
	        mask_dt = TYPE_HOST;                                                                            // An IPv6 mask given
	        position += 2;
	    } else if (header != 'i' && EtherAddressArg().parse(_words[position + 1], provided_mask.c, _context)) {  // An ethernet mask is given
	        mask_dt = TYPE_ETHER;
	        position += 2;
	    }
	    if (mask_dt && mask_dt != TYPE_ETHER && !provided_mask.u) {
	        _errh->error("zero mask ignored");
	        mask_dt = 0;
	    }
	    word = (position >= _words.size() - 1 ? String() : _words[position]);
    }

    // optional relational operation
    position++;                              // TODO after a qualifier word i guess we can start seeing one of these operators below; only with = or == we do not need to change anything. I suppose this is because acting with = is the standard method we are going to use when nothing is given too?
    if (word == "=" || word == "==")
	    /* nada */;
    else if (word == "!=")
	    primitive._isInternalOperatorInNegatedForm = true;
    else if (word == ">")
	    primitive._internalOperatorType = OP_GT;
    else if (word == "<")
	    primitive._internalOperatorType = OP_LT;
    else if (word == ">=") {
	    primitive._internalOperatorType = OP_LT;
	    primitive._isInternalOperatorInNegatedForm = true;
    } else if (word == "<=") {
	    primitive._internalOperatorType = OP_GT;
	    primitive._isInternalOperatorInNegatedForm = true;
    } else
	    position--;

    // now collect the actual data
    if (position < _words.size()) {              
	    word = _words[position];       // word; this is the current word we are handling
	    uint32_t wdata;
	    int wordType = lookup(word, primitive._internalPrimitiveType, primitive._transp_proto, wdata, _context, _errh); // wt stands for word type.
	    position++;  // TODO so after the host type and an optional operator sign like ==, !=, >=, >, <=, < we move our position one further and start checking for the data

	    if (wordType == -2)		// -2 means an ambiguous or incorrect word type
	        /* absorb word, but do nothing */
	        primitive._internalPrimitiveType = -2;

	    else if (wordType != -1 && wordType != TYPE_TYPE) {     // a word type != -1   or TYPE_TYPE   means I have a proper and real type I guess.
	        primitive._data = wordType;
	        primitive._u.u = wdata;

	    } else if (IntArg().parse(word, primitive._u.i))
	        primitive._data = TYPE_INT;

	    else if (header != 'e' && IP6AddressArg().parse(word, primitive._ip6Address, _context)) {        // TODO dit moeten we aanpassen en moet IPv6 adres zijn parse worden!
	        if (position < _words.size() - 1 && _words[position] == "mask" && IP6AddressArg().parse(_words[position+1], primitive._ip6AddressMask, _context)) {
		        position += 2;
		        primitive._data = TYPE_NET;
	        } else if (primitive._internalPrimitiveType == TYPE_NET && IPPrefixArg().parse(word, primitive._u.ip4, primitive._mask.ip4, _context))        // TODO ook hier werken met IPv6PrefixArg
		        primitive._data = TYPE_NET;
	        else
		        primitive._data = TYPE_HOST;
	    } else if (header != 'e' && IPPrefixArg().parse(word, primitive._u.ip4, primitive._mask.ip4, _context)) // TODO ook hier werken met IP6PrefixArg
	    	primitive._data = TYPE_NET;

	    else if (header != 'i' && EtherAddressArg().parse(word, primitive._u.c, _context))
	    	primitive._data = TYPE_ETHER;

	    else {
	    	if (primitive._internalOperatorType != OP_EQ || primitive._isInternalOperatorInNegatedForm)
	    		_errh->error("dangling operator near %<%s%>", word.c_str());
	    	position--;
	    }
    }

    if (position == startPosition) {
	    _errh->error("empty term near %<%s%>", word.c_str());
	    return position;
    }

    // add if it is valid
    if (primitive.check(_prev_prim, header, mask_dt, provided_mask, _errh) >= 0) {       // if this returns anything but 0 it is OK
	    primitive.compile(_program, _tree);                                                 // now we compile the primitive we have set before
	    if (negated)
	        _program.negate_subtree(_tree);
	    _prev_prim = primitive;                      // our previous primitive can be read with this variable; // TODO why do we need to know the previous premitive?
    }

    return position;
}

// TODO
// TODO     Hier start het parsen denk ik als het Classifier element wordt aangemaakt
// TODO
void
IP6Filter::parse_program(Classification::Wordwise::CompressedProgram &zprog, const Vector<String> &conf, int noutputs, const Element *context, ErrorHandler *errh)
{
    Classification::Wordwise::Program prog;
    Vector<int> tree = prog.init_subtree();

    // [QUALS] [host|net|port|proto] [data]
    // QUALS ::= src | dst | src and dst | src or dst | \empty
    //        |  ip | icmp | tcp | udp

    // TODO: welke combinaties zijn toegestaan? (en wat betekent die combinatie dan?) Dat wordt nergens vermeld. (bv. wat wil tcp port zeggen? gaat het hier om een src port of een dst port?)
    // TODO: een woordje info:  host captured traffic naar en van het opgegeven IP adres: bvb. host 172.18.5.4
    // TODO                     net captured traffic naar en van een een range van IP adressen: bvb. net 192.168.0.0/24
    // TODO => je kan er ook nog src of dst voor typen als je wil
    // TODO                                                     ==> om aan te tonen dat je enkel pakketten van respectievelijk naar het opgegeven IP adres/de range van opgegeven IP adressen wil ontvangen
    for (int argno = 0; argno < conf.size(); argno++) {             // Voor elke meegeven 'flow' doe het volgende
                                                                    // Bijvoorbeeld: Classifier(12/0800, -) heeft twee flows, 12/0800 en -
                                                                    // Nu op IPClassifier zijn die typisch wel anders en hebben we iets als
                                                                    // IPClassifier(ip vers 4, dst port 50) waarbij de twee flows dus de 'ip vers 4'-flow en de 
                                                                    // 'dst port 50'-flow zijn.
	    Vector<String> words;
	    separate_text(cp_unquote(conf[argno]), words);

	    if (words.size() == 0) {
	        errh->error("empty pattern %d", argno);
	        continue;           // ga onmiddellijk naar het volgende argument, dit argument is leeg en dus oninteressant (=> een argument is een 'flow' uit het vorig commentaarblok
	    }

	    PrefixErrorHandler cerrh(errh, "pattern " + String(argno) + ": ");      // ook deze zetten we klaar voor als het nodig is lijkt mij? want er is hier duidelijk nog geen error momenteel

	    // get slot

        // (het slotwoord is het woord dat 'allow' of 'deny' zegt tegen dat bepaald type stroom)
	    int slot = -Classification::j_never;                // het getal j_never is -2147483647, en dit getal betekent eigenlijk "drop packet". Als je output dit getal heeft dan betekent die output "drop packet" of zo.
	    {
	        String slotwd = words[0];
	        if (slotwd == "allow") {
	            slot = 0;
		        if (noutputs == 0)
		            cerrh.error("%<allow%> is meaningless, element has zero outputs");
	        } else if (slotwd == "deny") {
		        if (noutputs > 1)
		            cerrh.warning("meaning of %<deny%> has changed (now it means %<drop%>)");
	        } else if (slotwd == "drop")
		        /* nada */;
	        else if (IntArg().parse(slotwd, slot)) {
		        if (slot < 0 || slot >= noutputs) {
		            cerrh.error("slot %<%d%> out of range", slot);
		            slot = -Classification::j_never;
		        }
	        } else
		        cerrh.error("unknown slot ID %<%s%>", slotwd.c_str());  // for example if the first none blank character is a something like a bracket, or a nonnumeric number in general
	    }

	    prog.start_subtree(tree);

	    // check for "-"
	    if (words.size() == 1 || (words.size() == 2 && (words[1] == "-" || words[1] == "any" || words[1] == "all")))
	        prog.add_insn(tree, 0, 0, 0);           // deze instructie matcht altijd
	    else {
	        Parser parser(words, tree, prog, context, &cerrh);      // TODO als het geen streepje is, dan is het waarschijnlijk een complexere uitdrukking en die gaan we hier verwerken met een parser klasse die onze woordjes meekrijgt
// TODO voor onze eerste voorbeeldflow zou die dus de woordjes 'ip vers 4' meekrijgen, en voor onze twede voorbeeldflow de woordjes 'dst port 50'
	    int pos = parser.parse_expr_iterative(1);               // TODO oke cool ? gaat deze methode het zprog programma echt opbouwen? Let's watch & see!
	        if (pos < words.size())                                 // ik denk dat die normaal de positie gaat returnen waar er voor het eerst een typfout komt of zo in deze 'flow'-tekst, en anders dan geeft die een muug hoog getal terug ofzu wat dan wil zeggen dat het al het parsen goed is gelukt!
		        cerrh.error("garbage after expression at %<%s%>", words[pos].c_str());
	    }


	    prog.finish_subtree(tree, Classification::c_and, -slot);    // interessant: bij de laatste subtree van deze 'stroom' plaatsen we het negatief slot nummer er in :) -> dit is dus geen jump meer, maar dan weten we dat we er zijn geraakt

        click_chatter("let's print out the tree!!");
        for(int i = 0; i < tree.size(); i++) {
            click_chatter("tree[ %i ] = %i", i, tree[i]);
        }
    }


    if (tree.size())            // als tree.size() dus verschillend is van een lege tree dan doen we het volgende
	    prog.finish_subtree(tree, Classification::c_or, Classification::j_never, Classification::j_never);

    // TODO
    // TODO Een super dikke aanrader is die twee click_chatters hier te oncommentarieren om te kunnen zien wat het verschil is tussen het gewone programma en het geoptimizede + gecompresseerde programma . Misschien kunnen we na het gewoon optimize ook nog eens click_chatteren om te zien wat dat geeft!
    // TODO

    click_chatter("%s", prog.unparse().c_str());
    static const int offset_map[] = { offset_net + 8, offset_net + 3 };         // TODO is dit IPv4 gebonden? wat zijn die offset_net + 8 en offset_net + 3? Kunnen we die er uit laten? => bijkomende vraag: kunnen we die prog.optimize(...,...,...) er uit laten die eigenlijk die offset_maps verwacht als argument?
    prog.optimize(offset_map, offset_map + 2, Classification::offset_max);

    // Compress the program into _zprog.
    // It helps to do another bubblesort for things like ports.

    // TODO Waarvoor staat eigenlijk _zprog? Is dat 'gezipte prog'? Wat is het verschil tussen prog en _zprog? Bevat het _zprog programma minder instructies dan prog?
    prog.bubble_sort_and_exprs(offset_map, offset_map + 2, Classification::offset_max);     // TODO wtf is dat bubble sort gedoe?! :/
    zprog.compile(prog, PERFORM_BINARY_SEARCH, MIN_BINARY_SEARCH);

    // click_chatter("%s", zprog.unparse().c_str());


}

/*
* Configuration block
*/
int
IP6Filter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    IPFilterProgram zprog;                                          // bij de configuratie wordt ons zprog aangemaakt, dit gaat alle filter informatie bevatten
    parse_program(zprog, conf, noutputs(), this, errh);             // haar gaan we wat in tekst in ons script staat, omvormen tot zprog taal!
    if (!errh->nerrors()) {
	    _zprog = zprog;
	    return 0;
    } else
	    return -1;
}

String
IP6Filter::program_string(Element *e, void *)
{
    IP6Filter *ipf = static_cast<IP6Filter *>(e);
    return ipf->_zprog.unparse();
}

void
IP6Filter::add_handlers()
{
    add_read_handler("program", program_string);            // dit is dus die 'program' handler waarover gesproken werd in de handleiding bovenaan
}                                                           // program_string is een functie die de _zprog.unparse() teruggeeft


//
// RUNNING
//

// dit is een uitzonderingsgeval of zo??? waar je ook de lengte moet checken, das enkel nodig bij echt korte pakketten ofzu.... nog niet echt duidelijk
int
IP6Filter::length_checked_match(const IPFilterProgram &zprog, const Packet *p, int packet_length)
{
    const unsigned char *neth_data = p->network_header();
    const unsigned char *transph_data = p->transport_header();
    const uint32_t *pr = zprog.begin();
    const uint32_t *pp;
    uint32_t data = 0;

    while (1) {
	    int off = (int16_t) pr[0];
	    if (off + 4 > packet_length)
	        goto check_length;

        length_ok:
	    if (off >= offset_transp)
	        data = *(const uint32_t *)(transph_data + off - offset_transp);
	    else if (off >= offset_net)
	        data = *(const uint32_t *)(neth_data + off - offset_net);
	    else
	        data = *(const uint32_t *)(p->mac_header() - 2 + off);
	    data &= pr[3];
	    off = pr[0] >> 17;
	    pp = pr + 4;
	    if (!PERFORM_BINARY_SEARCH || off < MIN_BINARY_SEARCH) {
	        for (; off; --off, ++pp)
		    if (*pp == data) {
		      off = pr[2];
		       goto gotit;
		    }
	    } else {
	        const uint32_t *px = pp + off;
	        while (pp < px) {
		        const uint32_t *pm = pp + (px - pp) / 2;
		        if (*pm == data) {
		            off = pr[2];
		            goto gotit;
		        } else if (*pm < data)
		            pp = pm + 1;
		        else
		            px = pm;
	        }
	    }
	    off = pr[1];

        gotit:
	    if (off <= 0)
	        return -off;
	    pr += off;
	    continue;

        check_length:
	    if (off < packet_length) {
	        unsigned available = packet_length - off;
	        const uint8_t *c = (const uint8_t *) &pr[3];
	        if (!(c[3] || (c[2] && available <= 2) || (c[1] && available == 1)))
		        goto length_ok;
	    }
	    off = pr[1 + ((pr[0] & 0x10000) != 0)];
	    goto gotit;
    }
}

/* 
* Code starts here
*/
void
IP6Filter::push(int, Packet *p)
{
//    click_chatter("*pointer = ");
//    for(const unsigned char* pointer = p->mac_header(); pointer < p->network_header(); pointer++) {
//        click_chatter("%i ", *pointer);
//    }
//    click_chatter("\n");

    checked_output_push(match(_zprog, p), p); // push packet to output port 'match(_zprog, p)' , or KILL the packet if the port is out of range
                                              
                                              // match itself is a function who is defined inside ip6filter.hh, here the real stuff begins and it will return the port to 
                                              // which the packet needs to be sent.
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classification)
EXPORT_ELEMENT(IP6Filter)
