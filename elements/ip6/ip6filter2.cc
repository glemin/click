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
#include "ip6filter_classes.hh"
#include "ip6filter_parser.hh"
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

/*
void
IP6Filter::Primitive::simple_negate()
{
  assert(negation_is_simple());
  _isInternalOperatorInNegatedForm = !_isInternalOperatorInNegatedForm;
  if (_internalPrimitiveType == TYPE_PROTO && _mask.u == 0xFF)       // TODO why does the mask needs to be 0xFF ?
    _transp_proto = (_isInternalOperatorInNegatedForm ? UNKNOWN : _u.i);
}
*/


// parse 'test' on encountering it.




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

// This function handles transport layer protocols (such as TCP and UDP).
/*static void
add_exprs_for_proto(int32_t proto, int32_t mask, Classification::Wordwise::Program &program, Vector<int> &tree)
{
    if (mask == 0xFF && proto == IP_PROTO_TCP_OR_UDP) {         // 0xFF = 255 in decimaal
	    program.start_subtree(tree);
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(IP_PROTO_TCP << 16), htonl(0x00FF0000));  // = htonl(16711680) ; this is the TCP rule.
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(IP_PROTO_UDP << 16), htonl(0x00FF0000));  // = htonl(16711680) ; this is the UDP rule.
	    program.finish_subtree(tree, Classification::c_or);
    } else if (mask == 0xFF && proto >= 256)                    // 0xFF = 255 in decimaal
	    ; // nada 
    else
	    program.add_insn(tree, IP6Filter::offset_net + 8, htonl(proto << 16), htonl(mask << 16)); // proto << 16 and mask << 16, is used to bring the proto and mask values in the correct place into the packet.
}
*/

/*
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
*/
/* Helper function */

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
*/
// TODO
// TODO         deze functie wordt veel gecalled gedurende de configuratiefase; het wordt gebruikt bij het opbouwen van zprog  (zprog wordt dus gemaakt tijdens de configuratie fase maar dat wisten we wrs al!)
// TODO         Maar: wat doet ze net? Gaat ze het programma helemaal omzetten in zprog taal?? Let's watch & see!!
// TODO 


// TODO position might be currentPositionInWordsList


// TODO I suppose they mean to parse square brackets, however no documentation was added to this part of the code.
static int
parse_brackets(Primitive& prim, const Vector<String>& words, int pos, ErrorHandler* errh)       // TODO why does this have a primitive as an argument?
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
        if (cp_integer(combination.begin(), colon, 0, &fieldpos) == colon && cp_integer(colon + 1, combination.end(), 0, &len) == combination.end())
         goto non_syntax_error;
    } else if (comma < combination.end() - 1) {
        int pos2;
        if (cp_integer(combination.begin(), comma, 0, &fieldpos) == comma && cp_integer(comma + 1, combination.end(), 0, &pos2) == combination.end()) {
            len = pos2 - fieldpos + 1;
            goto non_syntax_error;
        }
    } else if (IntArg().parse(combination, fieldpos))
        goto non_syntax_error;
    errh->error("syntax error after %<[%>, expected %<[POS]%> or %<[POS:LEN]%>");
    return pos;

    non_syntax_error:
        errh->error("non syntax error");
/*int multiplier = 8;
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
 */
        return pos;
}

/* parsing and compilation */

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



String
IP6Filter::program_string(Element *e, void *)
{
    IP6Filter *ipf = static_cast<IP6Filter *>(e);
    return ipf->_zprog.unparse();
}

/* Handlers */
void
IP6Filter::add_handlers()
{
    add_read_handler("program", program_string);            // dit is dus die 'program' handler waarover gesproken werd in de handleiding bovenaan
}                                                           // program_string is een functie die de _zprog.unparse() teruggeeft


/* Running */

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
