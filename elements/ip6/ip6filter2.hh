#ifndef CLICK_IP6FILTER2_HH
#define CLICK_IP6FILTER2_HH
#include "elements/standard/classification.hh"
#include <click/element.hh>
CLICK_DECLS

/*
=c

IP6Filter(ACTION_1 PATTERN_1, ..., ACTION_N PATTERN_N)

=s ip6

filters IPv6 packets by contents

=d

Filters IPv6 packets. IP6Filter can have an arbitrary number of filters, which
are ACTION-PATTERN pairs. The ACTIONs describe what to do with packets,
while the PATTERNs are tcpdump(1)-like patterns; see IP6Classifier(n) for a
description of their syntax. Packets are tested against the filters in
order, and are processed according to the ACTION in the first filter that
matched.

Each ACTION is either a port number, which specifies that the packet should be
sent out on that port; 'C<allow>', which is equivalent to 'C<0>'; or 'C<drop>'
, which means drop the packet. You can also say 'C<deny>' instead of
'C<drop>', but see the compatibility note below.

The IP6Filter element has an arbitrary number of outputs. Input packets must
have their IPv6 header annotation set; CheckIP6Header and MarkIP6Header do
this.

=n

Every IP6Filter element has an equivalent corresponding IP6Classifier element
and vice versa. Use the element whose syntax is more convenient for your
needs.

B<Compatibility note>: 'C<deny>' formerly meant 'C<1>' if the element had at
least two outputs and 'C<drop>' if it did not. We decided this was
error-prone; now it just means 'C<drop>'. For now, however, 'C<deny>' will
print a warning if used on an element with more than one output.

=e

This large IP6Filter implements the incoming packet filtering rules for the
"Interior router" described on pp691-692 of I<Building Internet Firewalls,
Second Edition> (Elizabeth D. Zwicky, Simon Cooper, and D. Brent Chapman,
O'Reilly and Associates, 2000). The captialized words (C<INTERNALNET>,
C<BASTION>, etc.) are addresses that have been registered with
AddressInfo(n). The rule FTP-7 has a port range that cannot be implemented
with IP6Filter.

  IP6Filter(// Spoof-1:
           deny src INTERNALNET,
           // HTTP-2:
           allow src BASTION && dst INTERNALNET
              && tcp && src port www && dst port > 1023 && ack,
           // Telnet-2:
           allow dst INTERNALNET
              && tcp && src port 23 && dst port > 1023 && ack,
           // SSH-2:
           allow dst INTERNALNET && tcp && src port 22 && ack,
           // SSH-3:
           allow dst INTERNALNET && tcp && dst port 22,
           // FTP-2:
           allow dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-4:
           allow dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023 && ack,
           // FTP-6:
           allow src BASTION && dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-7 omitted
           // FTP-8:
           allow src BASTION && dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023,
           // SMTP-2:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port 25 && dst port > 1023 && ack,
           // SMTP-3:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port > 1023 && dst port 25,
           // NNTP-2:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port 119 && dst port > 1023 && ack,
           // NNTP-3:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port > 1023 && dst port 119,
           // DNS-2:
           allow src BASTION && dst INTERNAL_DNS
              && udp && src port 53 && dst port 53,
           // DNS-4:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port 53 && dst port > 1023 && ack,
           // DNS-5:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port > 1023 && dst port 53,
           // Default-2:
           deny all);

=h program read-only
Returns a human-readable definition of the program the IP6Filter element
is using to classify packets. At each step in the program, four bytes
of packet data are ANDed with a mask and compared against four bytes of
classifier pattern.

=a

IP6Classifier, Classifier, CheckIP6Header, MarkIP6Header, 
AddressInfo, tcpdump(1) */

enum {  /* temporarily */
    // if you change this, change click-fastclassifier.cc also
    // if you change this, also update the same enum in ip6filter_classes.cc
    offset_mac = 0,
    offset_net = 256,       
    offset_transp = 512,

    // fictive offset values of IPv6 extension headers
    offset_hop_by_hop = 700,    // kunnen ook iets andes kiezen, en telkens elk ander type IPv6 offset 100 verder laten beginnen
    offset_destination_options = 800,
    offset_routing = 900,
    offset_fragment = 1000,
    offset_authentication_header = 1100,
    offset_encapsulating_security_payload = 1200,
    offset_mobility = 1300
};

class IP6Filter : public Element { public:

    IP6Filter() CLICK_COLD;     // CLICK_COLD is an indication to the compiler that this function is rarely used.
    ~IP6Filter() CLICK_COLD;    // CLICK_COLD is an indication to the compiler that this function is rarely used.

    const char *class_name() const		{ return "IP6Filter"; }
    const char *port_count() const		{ return "1/-"; }
    const char *processing() const		{ return PUSH; }
    // this element does not need AlignmentInfo; override Classifier's "A" flag
    const char *flags() const			{ return ""; }              // TODO We hebben schijnbaar geen flags. Wat is eigenlijk zo'n flag en waarvoor dient het?
    bool can_live_reconfigure() const	{ return true; }            // TODO Wat betekent deze functie? Wat houdt live herconfigureren in?

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;     // CLICK_COLD is an indication to the compiler that this function is rarely used.
    void add_handlers() CLICK_COLD;                                 // CLICK_COLD is an indication to the compiler that this function is rarely used.

    void push(int port, Packet *packet);

    typedef Classification::Wordwise::CompressedProgram IPFilterProgram;        // Classification::Wordwise::CompressedProgram   ==   IPFilterProgram

    static void parse_program(IPFilterProgram &zprog,
			      const Vector<String> &conf, int noutputs,
			      const Element *context, ErrorHandler *errh);
    static inline int match(const IPFilterProgram &zprog, const Packet *p);

 
    enum {
        // (2) Most of the time (?) or at least often, we have on of these
	    SOURCE = 1, DEST = 2, SOURCE_AND_DEST = 3, SOURCE_OR_DEST = 4       // ook conjunction achtige dingen gemixt met source en destination adressen???
    };

    enum {
        // (3) Normally we should always have on of these (I can't think of a particular situation where this is not the case)
	    OP_EQ = 0, OP_GT = 1, OP_LT = 2             // dit zijn conjunctions denk ik :) :/
    };


    /* config */
    enum {
	    PERFORM_BINARY_SEARCH = 1,              // 1 = TRUE !!!
	    MIN_BINARY_SEARCH = 7                   // enkel als we minimum 7 items in onze lijst hebben doen we de moeite om een binary search te doen
                                                // wat doen we bij minder dan 7 items? => wel we doorlopen gewoon de lijst.
    };

    // TODO
    // TODO         Een primitive heeft altijd een IP adres als in een PrimitiveData in zich   ............. denk ik => jup is zo, zelfs 2: de _u en de _mask
    // TODO
    // Stelt een primitive 1 vd mogelijke volledige flows voor een pkt kan volgen?
    // Of is een kleinere eenheid binnen een bepaalde flow??

    // hoeveel primitives worden er aangemaakt voor een setup met 3 flows?????
    // hmmm.. interesting, i want to the answer

    // Resembles a Wireshark Primitive.


protected:  // Because it is used by IPClassifier?
    IPFilterProgram _zprog; // dezen brol moet ge heel low level instructies meegeven! Daarmee wil die gevoed worden en op basis van die low level info kan hij het 'verkeer' regelen, en ieder pakket naar de juiste output loodsen.

private:
    // is looking something up in the global database of NameInfo, I suppose..........
    static int lookup(String word, int type, int transp_proto, uint32_t &data, const Element *context, ErrorHandler *errh); // dees zoekt iet op, wa is oek nog ni zu duidelijk

    static int length_checked_match(const IPFilterProgram &zprog, const Packet *p, int packet_length);

    static String program_string(Element *e, void *user_data); // wtf is dit? is dit een string versie van euh... u hele klasse ofzu??? mor iet mottig precies!!!
};


/*
inline bool
IP6Filter::Primitive::negation_is_simple() const    // vaag
{
    if (_internalPrimitiveType == TYPE_PROTO)
	    return true;
    else if (has_transp_proto())            // TODO waarom is hier de negatie moeilijk?   // if it has a transp proto, the the negation is hard, but why?
	    return false;
    else
	    return _internalPrimitiveType == TYPE_HOST || (_internalPrimitiveType & TYPE_FIELD) || _internalPrimitiveType == TYPE_IPFRAG;      // if _internalPrimitiveType is equal to one of those 3 return true, otherwise return false (then we have an unknown _internalPrimitiveType I guess), you need to try them all 3 out if needed
}
*/

// TODO
// TODO     Hier gaat het zprog de in zichzelf opgeslagen zprog boom op de proef gesteld worden
// TODO     -> pakketten gaan gematcht worden met de boom van zprog hier
// TODO     => blijkbaar moeten we het data gedeelte schijden van het header gedeelte -> 
// TODO
/*
* Here the real program starts. It will return as a number the port to which the packet needs to be sent to.
* It expects as arguments the packet to be inspected and some suspicious 'zprog' argument.
*/
inline int
IP6Filter::match(const IPFilterProgram &zprog, const Packet *p)     // wat bevat dat IP filter programma? bevat da nen boom die ge door moet wandelen? En wa voor 1ne just? Nen operatie boom ofzu met & en || tekentjes ofzuiet?? En daartussen dan operaties. Ne soort van parse tree ofzu?? En moet ge daar binair in zoeken?? hmmm da binair zoeken is nog mor wa vreemd!!!
{
    int packet_length = 0;  // we start building up the packet length from here
    
    packet_length += p->network_length();       // we start already by adding the network_length, now we still need to add some other stuff.

    if (p->network_length() > p->network_header_length())
	    packet_length += offset_transp - p->network_header_length();    // offset_transp is a constant, it is equal to 512
    else
	    packet_length += offset_net;    // offset_net is a constant, it is equal to 256

    if (zprog.output_everything() >= 0)
	    return zprog.output_everything();
    else if (packet_length < (int) zprog.safe_length())
	    // common case never checks packet length
        
        // alhoewel het een beetje vreemd lijkt, ik denk dat hier het ongewone geval staat waarbij je wel de lengte gaat moeten blijven checken! De lengte is te klein hier.
	    return length_checked_match(zprog, p, packet_length);

    // hier komt het gewone geval denk ik waar je bijna nooit de packet lengte moet checken
    const unsigned char *neth_data = p->network_header();
    const unsigned char *transph_data = p->transport_header();

    const uint32_t *programInstruction = zprog.begin();

    const uint32_t *pp;                         // is mij nog nie duidelijk wat dit is!!!!
    uint32_t data;              // gaat het hier om een IPv4 adres, of om totaal andere shizzle!!!
    while (1) {
	    int off = (int16_t) programInstruction[0];              // het eerste uit die array geeft blijkbaar nen offset terug, waarvoor die cast dient is mij niet duidelijk
        click_chatter("de offset genaamd 'off' is nu gelijk aan: %i", off);	    
        
        // offset indicates (a) on which header in the packet we will be working on, and (b) where exactly in the header we will be working

        // The system to determine where we will be working is as follows. First we will investigate which base number we have.
        //
        // For instance:
        // Base number 0 means we will be working in the Ethernet header.
        // Base number 256 means we will be working in the network header (which can be either IPv4 or IPv6)
        // Base number 512 means we will be working in the transport layer (which can for instance be UDP or TCP)
        // Base number 700 means we will be working in the Hop-by-hop Options IPv6 extension header
        // Base number 800 means we will be working in the Destination Options IPv6 extension header
        // Base number 900 means we will be working in the Routing IPv6 extension header
        // Base number 1000 means we will be working in the Fragment IPv6 extension header
        // Base number 1100 means we will be working in the Authentication Header (AH) IPv6 extension header
        // Base number 1200 means we will be working in the Encapsulation Security Payload (ESP) IPv6 extension header
        // Base number 1300 means we will be working in the Mobility IPv6 extension header

        // The base number can be detrmined by looking into which range of values your 'int off' variable  falls. What you need to do is figuering out what first base number (i.e. 0, 256, 700, 800, 900, 1000, 1100, 1200, 1300) you will encounter first when you start decreasing your 'int off' value. As an example, if you have number 856, your base number would be 800 (this is not an actual example but just a theoretical one just to get the point). If you have the number 1180 your base number would be 1100 and if you would have 260 your base number would be 256.
        
        // From the moment you know your base number, we know about which header we are talking. Now to know which specific value we want to work with we look at the remaining value. So for instance when your number would be 268 we look at byte '2' in the network header. If your vlue is 701 we will look at byte '1' in the Hop-by-hop Options IPv6 extension header, and finally if your value would be 900 you look at byte '0' in the Routing IPv6 extension header.
        if (off >= offset_mobility) { // working on: IPv6 Mobility extension header

        } else if (off >= offset_encapsulating_security_payload) { // working on: IPv6 Destination Options extension header

        } else if (off >= offset_authentication_header) { // working on: IPv6 Authentication Header (AH) extension header

        } else if (off >= offset_fragment) { // working on: IPv6 Fragment extension header

        } else if (off >= offset_routing) { // working on: IPv6 Routing extension header

        } else if (off >= offset_destination_options) { // working on: IPv6 Destination Options extension header

        } else if (off >= offset_hop_by_hop) { // working on: IPv6 Hop-by-Hop Options extension header

        } else if (off >= offset_transp) // working on: trasnport layer
	        data = *(const uint32_t *)(transph_data + (off - offset_transp));
	    else if (off >= offset_net) // working on: network layer
	        data = *(const uint32_t *)(neth_data + (off - offset_net));
	    else // working on: ethernet layer
	        data = *(const uint32_t *)(p->mac_header() - 2 + off);          // TODO waarom -2?
	    data &= programInstruction[3];                  // we &'en dit met dit met de mask denk ik (zie classification.cc -> CompressedProgram::compile(..., ..., ...))
                                        // TODO zit op plek 3 steeds het masker? (ook wel the mask genoemd)?
	    off = programInstruction[0] >> 17;              // kijk naar classification.cc -> CompressedProgram::compile(...) => off wordt hier hergebruikt en betekent nu het # parameters denk ik! met heeft een variabele willen uitsparen denk ik.
	    pp = programInstruction + 4;                    // TODO hier zit de eerste echte value waar we moeten vergelijken, mogelijk zijn 't er meer!!!!
	    if (!PERFORM_BINARY_SEARCH || off < MIN_BINARY_SEARCH) {        // ALS onze offset te laag is voor een BINARY SEARCH of we hebben hem handigmatig uitgeschakeld, dan doen we iets anders en wel wat hier staat
	        for (; off; --off, ++pp)    // onze pp wordt iet waarvan we willen weten of die uiteindelijk aan data gelijk gaat zijn, dan hemme we het gevonne, wa da ook moge zen....... die data zelf is ook mor uber vaag....... ooooofffffffff wacht is, mss is da................
		        if (*pp == data) {              // hier doen we geen binary search, we wandelen van Links naar Rechts tot we het element tegenkomen!
		            off = programInstruction[2]; // offset wordt hier nog eens hergebruikt
                                 // TODO hier staat naar welk nummer je moet springen als de zoektocht succesvol was => blijkbaar kan er ook op bit 1 het negatieve getal staan, is dat geval moet je het teken omkeren
                                 // TODO het moet maar met 1 v/d values matchen en dan gaan we naar pr[2]
		            goto gotit;                 // we got it, yeah yeah     buuuuuutttt... what did we got?? we got something important it seems!!!
		        }
	        } 
        else {                          // Enkel als we super veel waarden hebben waarmee gecheckt moet worden, dan brengen we die waarden onder in een boom
                                        // In deze boom werden de waarden allemaal op waarde/'key' gerangschikt via een bubble sort
                                        // Dit vergemakelijkt het uiteindelijk terugvinden van de gezochte waarde
	        const uint32_t *px = pp + off;
	        while (pp < px) {
		        const uint32_t *pm = pp + (px - pp) / 2;
		        if (*pm == data) {        
		            off = programInstruction[2];          
		            goto gotit;
		        } else if (*pm < data)      
		            pp = pm + 1;
		        else              
		            px = pm;
	        }
	    }
	    off = programInstruction[1];          // TODO hier staat naar welk nummer je moet springen/of hoeveel nummer je verders moet springen (=> kan ook nog wel...) als je zoektocht onsuccesvol was => blijkbaar kan er ook op bit 1 het negatieve getal staan, is dat het geval dan moet je het teken omkeren

        gotit:
        if (off <= 0)
            return -off;
        programInstruction += off;      // Hier moeten we dus inderdaad heenspringen!! of anders geeft het hoeveel stappen je verder moet tellen, kan ook nog wel!!! we tellen het wel bij de huidige positie waar we ons bevinden!!! dus dat laatste zou ook nog wel eens goed kunnen!!!
    }
}



CLICK_ENDDECLS
#endif
