/*
 * markip6header.{cc,hh} -- element sets IP6 Header annotation
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
#include "markip6header.hh"
#include <clicknet/ether.h>
#include <clicknet/icmp6.h>
#include <clicknet/ip6_extension.h>
#include <click/args.hh>
#include <clicknet/ip6.h>
#include <click/list.hh>
CLICK_DECLS

MarkIP6Header::MarkIP6Header()
{
}

MarkIP6Header::~MarkIP6Header()
{
}

int
MarkIP6Header::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _offset = 0;
  return Args(conf, this, errh).read_p("OFFSET", _offset).complete();
}


// helper function

// @param currentLocationInPacket How many bytes are we already separated from the beginning of the beginning of the fixed IPv6 header. We use this number to make approriate ICMPv6 error messages, because we need to tell ICMPv6 how far we exactly are in the chain of IPv6 headers/extension headers. Initially this is zero.
// @param errorEncountered an error has been encountered while handling a specific header or extension header, this can for instance indicate for instance that a header that can only appear twice, appeared three times or that a header that should appear only once, appeared twice.
// @param sourceAddress Is given because we need the sourceAddress when we need to send back an ICMPv6 error message when something goes wrong. We need it to calculate the checksum (when calculating the checksum of an UDP/ICMPv6 packet you need to work with a pseudo header which means that just before the actual header where you are going to do your checksum you need to add some additionatiol information. But this stuff is all done behind the scenes in the function 'click_in_cksum_pseudohr_raw') but also to send the message back with the correct sourceAddress (TODO or at least I think).
// @param destinationAddress Is given because we need the destinationAddress when we need to send back an ICMPv6 error message when something goes wrong. The rest of the inforamtion is identical to what is written above but substitute sourceAddress by destinationAddress.
void* MarkIP6Header::handleExtraHeader(void *previousHeader, uint8_t headerNumber, uint8_t &nextHeaderNumber, int &currentLocationInPacket, bool& errorEncountered, Packet* p, in6_addr sourceAddress, in6_addr destinationAddress) {
    
    switch(headerNumber) {
        case 0:
            // ICMPv6 error, Hop-By-Hop should only appear only once and firt in the packet. If it is not found during the special treatment at the strart it is known that this sort of packet should not by any means be encountered again somewhere.
            errorEncountered = true;

            // TODO ICMPv6 error
            return 0;       // TODO i guess 0?? what should i return else??

        case 60:
            if (timesDestinationHeaderSeen == 0) {
                DestinationHeader* destinationOptionsHeader = reinterpret_cast<DestinationHeader*>(previousHeader + 1);
                nextHeaderNumber = destinationOptionsHeader->next_header;
                p->setDestinationOptions1AnnotationHeader((unsigned char*) destinationOptionsHeader);
                timesDestinationHeaderSeen++;

                return destinationOptionsHeader;
             } else if (timesDestinationHeaderSeen == 1) {
                DestinationHeader* destinationOptionsHeader = reinterpret_cast<DestinationHeader*>(previousHeader + 1);
                nextHeaderNumber = destinationOptionsHeader->next_header;
                p->setDestinationOptions2AnnotationHeader((unsigned char*) destinationOptionsHeader);
                timesDestinationHeaderSeen++;

                return destinationOptionsHeader;

             } else {
                // error header appeared 3 times and should appear at most 2 times
                p->kill();

                errorEncountered = true;    // indicate that just some sort of error was encountered, this is done to stop the exterior while-loop

                // send an ICMPv6 paramater problem error message
		        int tailroom = 0;
		        int packetsize = sizeof(click_icmp6_paramprob);     // + sizeof(click_ip6) + sizeof(click_ether) ?
	            int headroom = sizeof(click_ip6) + sizeof(click_ether); // of = 0? indien we er voor kiezen om het packet hier ineens helemaal ge-encapped buiten te sturen.

		        WritablePacket *packetWithICMPv6ErrorMessage = Packet::make(headroom,0,packetsize, tailroom);
                click_icmp6_paramprob* icmp6ParameterProblem = (click_icmp6_paramprob*) packetWithICMPv6ErrorMessage->data();


/*
    uint8_t icmp6_type;		// one of the ICMP_TYPE_*'s above
    uint8_t icmp6_code;		// one of the ICMP6_CODE_*'s above 
    uint16_t icmp6_cksum;   // 16 1's comp csum 
    uint32_t icmp6_pointer;	 // which octect in orig. IP6 pkt was a problem
*/
                icmp6ParameterProblem->icmp6_type = 4; // RFC 2463 indicates that this should be '4' for this type op error message
                icmp6ParameterProblem->icmp6_code = 1; // RFC 2463 indicates that this should be '1' for this type op error message, '1' here means literally "unrecognized Next Header type encountered", which is the type of error we encountered.
        // TODO        icmp6ParameterProblem->icmp6_cksum = in6_cksum(sourceAddress, destinationAddress, sizeof(click_icmp6_paramprob), 58, (unsigned char*) icmp6ParameterProblem, 
                icmp6ParameterProblem->icmp6_pointer = currentLocationInPacket;

                output(1).push(packetWithICMPv6ErrorMessage);
             }
        case 43:
            if(timesRoutingHeaderSeen == 0) {
                RoutingHeader* routingHeader = reinterpret_cast<RoutingHeader*>(previousHeader + 1);
                nextHeaderNumber = routingHeader-> next_header;
                p->setRoutingAnnotationHeader((unsigned char*) routingHeader);
                
                timesRoutingHeaderSeen++;
            } else {
                // ICMPv6 error
            }
        case 44:
            if(timesFragmentHeaderSeen == 0) {
                FragmentationHeader* fragmentHeader = reinterpret_cast<FragmentationHeader*>(previousHeader + 1);
                nextHeaderNumber = fragmentHeader->next_header;
                p->setFragmentationAnnotationHeader((unsigned char*) fragmentHeader);

                timesFragmentHeaderSeen++;
            } else {
                // ICMPv6 error
            }

        case 135:
    /*        if(timesMobilityHeaderSeen == 0) {
                MobilityHeader* mobilityHeader = reinterpret_cast<MobilityHeader*>(previousHeader + 1);
                nextHeaderNumber = mobilityHeader->next_header;
                p->setMobilityAnnotationHeader(mobilityHeader);

                timesMobilityHeaderSeen++;
            } else {
                // ICMPv6 error
            } */

        default:
            break;
        
    }
    return 0; // voorlopig
}

// check whether the nextHeaderNumber given in the IPv6 fixed header or IPv6 extension header points to a valid nextHeader
bool isValidHeaderNumber(int nextHeaderNumber) {   
    if (nextHeaderNumber == 60 || nextHeaderNumber == 43 || nextHeaderNumber == 44 || nextHeaderNumber == 135 || nextHeaderNumber == 0) {    // 0 is also added to the list while this was technically not needed, but we prefer to do it this way, if we encounter a '0' (Hop-By-Hop extension header) we need to send back an ICMP Error packet to indicate that it appeared twice. Because as indicated in the comments above, if a Hop-By-Hop extension header would have been available, it should have appeared right at the start and should have been handled there using our "so called special treatment" (which is in fact not so special at all, it's just called that way because it happens at a special point and Hop-by-Hop is handled a bit different from the others because it is the only one with a specific position. Namely it should only appear as a first extension header, otherwise this is a fault).
        return true;
    } else {
        return false;
    }
}

void MarkIP6Header::push(int, Packet *p)    // first argument is "port" but since we do not need the input port we leave the name of the parameter out to get rid of compiler warnings
{
    // starting point
    click_ip6* fixedHeader = (click_ip6*)(p->data() + _offset);
    // set the IPv6 fixed pointer (=> pointer pointing to the fixed part of the IPv6 packet that is available in every IPv6 packet)
    p->set_network_annotation_header((unsigned char*) fixedHeader);
    
    uint8_t nextHeaderNumber = fixedHeader->ip6_ctlun.alt4.next_header;
    click_chatter("1) de nextHeaderNumber is %i", nextHeaderNumber);
    int currentLocationInPacket = 0;
    bool errorEncountered = false;

    void * potentialExtraHeader;

    if(nextHeaderNumber == 0) {     // it is a Hop-By-Hop extension header, we give this sort of header a special treatment on the because it should only appear first.
        HopByHopHeader* hopByHopExtensionHeader = (HopByHopHeader*) fixedHeader;
        p->setHopByHopAnnotationHeader((unsigned char*) hopByHopExtensionHeader);
        nextHeaderNumber = hopByHopExtensionHeader->next_header;
        click_chatter("2) de nextNextHeaderNumber is %i", nextHeaderNumber);

        if (!(nextHeaderNumber == 59)) {      // if it is '59' we do not need to check any further, because '59' means no next header
            click_chatter("hier binnengegaan");
            void* nextHeader = ((unsigned char*) (hopByHopExtensionHeader + 1) + (8 * hopByHopExtensionHeader->hdr_ext_len)); 
            potentialExtraHeader = handleExtraHeader(hopByHopExtensionHeader + 1,hopByHopExtensionHeader->next_header,nextHeaderNumber,currentLocationInPacket,errorEncountered, p, fixedHeader->ip6_src, fixedHeader->ip6_dst); // here we start from the HopByHopExtension header (because we have one at the start)            
        }




    } else {    // normal case we start with the first real potential header, starting from the fixedHeader
        potentialExtraHeader = handleExtraHeader(fixedHeader + 1, fixedHeader->ip6_ctlun.alt4.next_header, nextHeaderNumber, currentLocationInPacket, errorEncountered, p, fixedHeader->ip6_src, fixedHeader->ip6_dst);
    }

    click_chatter("b");


    while ( isValidHeaderNumber(nextHeaderNumber) && !errorEncountered ) {
        potentialExtraHeader = handleExtraHeader(potentialExtraHeader, nextHeaderNumber, nextHeaderNumber, currentLocationInPacket, errorEncountered, p, fixedHeader->ip6_src, fixedHeader->ip6_dst);
    }

    click_chatter("x");

    if(!errorEncountered) {
        click_chatter("y");
        output(0).push(p);      // if no output occured we need to push the packet on which we have placed those new annotation headers onto port 0
    }
    // if actually errors did occur we don't need to do anything at all anymore, since we have already pushed an ICMPv6 error packet then; in the handleExtreaHeader function

}


CLICK_ENDDECLS
EXPORT_ELEMENT(MarkIP6Header)
