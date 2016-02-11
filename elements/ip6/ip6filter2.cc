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

// lege constructor
IP6Filter::IP6Filter()          // TODO do we need to give _transp_proto a default value?
{
}

// lege destructor
IP6Filter::~IP6Filter()
{
}


/* must be a member of the of the different Primitive types, you can override the function with the alternative version in the IPNextHeaderPrimtive */
void
IP6Filter::Primitive::simple_negate()
{
  assert(negation_is_simple());
  _isInternalOperatorInNegatedForm = !_isInternalOperatorInNegatedForm;
  if (_internalPrimitiveType == TYPE_PROTO && _mask.u == 0xFF)       // TODO why does the mask needs to be 0xFF ?
    _transp_proto = (_isInternalOperatorInNegatedForm ? UNKNOWN : _u.i);
}



// parse 'test' on encountering it.
int
IP6Filter::Parser::parse_primitive(int position, bool negatedSignSeen)    // parse het test gedeelte uit de grammatica
{
    currentWord = _words[position];

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


    if (!(position + 1 <= _words.size())) { /* all qualifiers are followed by at least some data */
        // throw error + return
        return -10; /* -10 ook nog veranderen */
    }
  
    if (currentWord == "ip") {

        if (_words[position+1] == "vers") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */
                primitive = new IPVersionPrimitive();
                primitive->operator_ == _words[position+2];
                primitive->versionNumber = atoll([position+3].c_str());    /* no error handling we might want to use boost::lexical_cast */
                primitive->compile();
               
                return position + 4;
            } else {            
                primitive = new IPVersionPrimitive();
                primitive->operator_ = "==";
                primitive->versionNumber = atoll([position+2].c_str());    /* no error handling we might want to use boost::lexical_cast */
                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "dscp") {
           if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */
                primitive = new IPDSCPPrimitive();
                primitive->operator_ = _words[position+2];
                primitive->dscpValue = atoll([position+3].c_str());
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPDSCPPrimitive();
                primitive->operator_ = "==";
                primitive->dscpValue = atoll([position+2].c_str());
                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "ce") {
        
        } else if (_words[position+1] == "ect") {
        
        } else if (_words[position+1] == "flow") {
           if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */    
                primitive = new IPFlowLabelPrimitive();
                primitive->operator_ = _words[position+2];
                primitive->flowLabelValue1 = atoll(_words[position+3].c_str());
                primitive->flowLabelValue2 = atoll(_words[position+3].c_str()) >> 16;
                primitive->compile();
	        
                return position + 4;
            } else {
                primitive = new IPFlowLabelPrimitive();
                primitive->operator_ = "==";
                primitive->flowLabelValue1 = atoll(_words[position+2].c_str());
                primitive->flowLabelValue2 = atoll(_words[position+2].c_str()) >> 16;
                primitive->compile();
                
                return position + 3;        
            }
        } else if (_words[position+1] == "plen") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPPayloadLengthPrimitive();
                primitive->operator_ =_words[position+2];
                primitive->payloadLength = atoll(_words[position+3].c_str());
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPPayloadLengthPrimitive();
                primitive->operator_ = "==";
                primitive->payloadLength = atoll(_words[position+2].c_str());
                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "nxt") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPNextHeaderPrimitive();
                primitive->operator_ == _words[position+2];
                primitive->nextHeader = atoll(_words[position+3].c_str());
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPNextHeaderPrimitive();
                primitive->operator_ = "==";
                primitive->nextHeader = atoll(_words[position+2].c_str());
                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "hlim") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPHopLimitPrimitive();
                primitive->operator_ = _words[position+2];
                primitive->hopLimit = atoll(_words[position+3].c_str());
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPHopLimitPrimitive();
                primitive->hopLimit = atoll(_words[position+2].c_str());
                primitive->compile();
                
                return position + 3;
        } else {
            /* an error occured: throw an error and return */
            return -10;
        } 
    } else if (_words[position] == "src") {  /* this must be followed by host or net keyword */
        if (_words[position+1] == "host") {
            primitive = new IPHostPrimitive();
            primitive->source_or_dest = "host";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive->operator_ = _words[position+3];
                primitive->ip6Address = IP6AddressArg().parse(_words[position+3], 0b11111111111111111111111111111111 , _context);
                primitive->compile();
                
                return position + 4;
            } else {
                primitive->operator_ = "==";
                primitive->ip6Address = IP6AddressArg().parse(_words[position+2], 0b11111111111111111111111111111111 , _context);
                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "net") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPNetPrimitive();
                primitive->operator_ = _words[position+2];
                
                if(!IP6PrefixArg().parse(_words[position+3], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->primitiveOperator = _words[position+3];
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPNetPrimitive();
                primitive->operator_ == "==";
                
                if(!IP6PrefixArg().parse(_words[position+2], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */

                primitive->compile();
                
                return position + 3;
            }
        } else if (_words[position+1] == "ether" && _words[position+2] == "host") {
            if (_words[position+3] == "==" || _words[position+3] == ">" || _words[position+3] == ">=" || _words[position+3] == "<=" || _words[position+3] == "<" 
            || _words[position+3] == "!=") {
                primitive = new EtherHostPrimitive();
                
//              if(!EtherAddressArg()            
            
            } else {
            
            }
        } else {
            // throw error + return
            return -10; /* -10 ook nog veranderen */
        }
	    
    } else if (_words[position] == "dst") {  /* this must be followed by host or net keyword */
        if (_words[position+1] == "host") {
            primitive = new IPHostPrimitive();
            primitive->source_or_dest = "dst";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive->operator_ == _words[position+2];
                if(!IP6AddressArg().parse(_words[position+3], primitive->ip6Address, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPHostPrimitive();
                primitive->operator_ = "==";
                if(!IP6AddressArg().parse(_words[position+2], primitive->ip6Address, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->primitiveOperator = _words[position+2];
                primitive->compile();
                
                return position + 3;                
            }
        } else if (_words[position+1] == "net") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPNetPrimitive();
                primitive->operator_ = _words[position+2];
                
                if(!IP6PrefixArg().parse(_words[position+3], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->compile();
                
                return position + 4;
            } else {
                primitive = new IPNetPrimitive();
                primitive->operator_ = "==";
                if(!IP6PrefixArg().parse(_words[position+2], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->compile();
                
                return position + 3;
            }
        } else {
            // throw error + return
            return -10; /* -10 ook nog veranderen */
        }    
	} else if (currentWord == "ether") {    // wellicht 'ether host'
        if (_words[position+1] == "host") {
            primitive->source_or_dest = "src or dst";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new EtherHostPrimitive();
                primitive->operator_ = _words[position+2];
                if(!EtherAddressArg().parse(_words[position+3], primitive->etherAddress, _context)) {
                    return -10; /* parsing failed */
                }
                return position + 4;
                
            
        }
	}
	
    if (negatedSignSeen)
        _program.negate_subtree(_tree);

    return position;
}



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
    if (_internalPrimitiveType < 0) /* NOT SET => ERROR */
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
		            _srcdst = prev_prim._srcdst;    /* wtf allowing a previous source or dest? No fucking way */
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
