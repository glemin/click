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
#include <iostream>
CLICK_DECLS

IP6Filter::IP6Filter()
{
}

IP6Filter::~IP6Filter()
{
}

/*
* Configuration block
*/
int
IP6Filter::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Classificatoin::Worswise::Program prog;
    Vector<int> tree = prog.init_subtree();

    for (int i = 0; i < conf.size(); i++) {
        Lexer lexer(conf);
        Vector<String> tokens = lexer.lex();
        if (words.size() == 0) {
            errh->error("IPFilter argument number %i+1 was empty");
            continue;
        }
        if (words.size() == 1) {
            cerrh.error("IPFilter argument number %i only contained one argument and should at least contain a slot token followed by an actual instruction);
        }
        
        int slot = -1;  // slots isn't set yet       
        String slotToken = tokens[0];   // the first token always contains the slot token
        
        // testing the slot token
        if (IntArg().parse(slotToken, slot)) {  // old C function, the parsed slot token will be placed in the integer slot
            if (slot < 0) || slot >= noutputs) {
                cerrh.error("The slot token must be in of range, but is out of range. The slot token given was %<%d%>", slot);
            }
        } else {
            cerrh.error("The slot token must be an integer but is something else, namely %<%s>%", slotToken.c_str());
        }

        // slot token test succeeded so we can go further
	    program.start_subtree(tree);    // internal subtree structure is an array and we "need to help this function" from the outside, since it is not self contained
	    
	    // check whether the fake condition "-" was found that matches everything
	    if (words.size() == 2 && tokens[1] == "-") {
	        program.add_insn(tree, 0, 0, 0);       // a fake condition that matches everything
	    }
	    
	    Parser parser(tokens);
	    parser.parse(program, tree, errh);
	    
	    
	    
	    


	    // check for "-"
	    if (words.size() == 1 || (words.size() == 2 && (words[1] == "-" || words[1] == "any" || words[1] == "all")))
	        prog.add_insn(tree, 0, 0, 0);           // deze instructie matcht altijd
	    else {
	        Parser parser(words, tree, prog, context, &cerrh);      // TODO als het geen streepje is, dan is het waarschijnlijk een complexere uitdrukking en die gaan we hier verwerken met een parser klasse die onze woordjes meekrijgt
// TODO voor onze eerste voorbeeldflow zou die dus de woordjes 'ip vers 4' meekrijgen, en voor onze twede voorbeeldflow de woordjes 'dst port 50'


	  
	        int pos = parser.parse();               // TODO oke cool ? gaat deze methode het zprog programma echt opbouwen? Let's watch & see!
	        if (pos < words.size())                                 // ik denk dat die normaal de positie gaat returnen waar er voor het eerst een typfout komt of zo in deze 'flow'-tekst, en anders dan geeft die een muug hoog getal terug ofzu wat dan wil zeggen dat het al het parsen goed is gelukt!
		        cerrh.error("garbage after expression at %<%s%>", words[pos].c_str());
	    }


	    prog.finish_subtree(tree, Classification::c_and, -slot);    // interessant: bij de laatste subtree van deze 'stroom' plaatsen we het negatief slot nummer er in :) -> dit is dus geen jump meer, maar dan weten we dat we er zijn geraakt

        click_chatter("let's print out the tree!!");
        for(int i = 0; i < tree.size(); i++) {
            click_chatter("tree[ %i ] = %i", i, tree[i]);
        }
        
    }

    parse_program(conf, noutputs(), this, errh);
    if (!errh->nerrors()) {
	    _zprog = zprog;
	    return 0;
    } else
	    return -1;
}

/* parsing and compilation */

// TODO
// TODO     Hier start het parsen denk ik als het Classifier element wordt aangemaakt
// TODO
void
IP6Filter::configure(const Vector<String> &conf, int noutputs, const Element *context, ErrorHandler *errh)
{
    Classification::Wordwise::Program prog;
    Vector<int> tree = prog.init_subtree();

    for (int argno = 0; argno < conf.size(); argno++) {           
	    Vector<String> words = separate_text(cp_unquote(conf[argno]));

	    if (words.size() == 0) {
	        errh->error("empty pattern %d", argno);
	        continue;           // ga onmiddellijk naar het volgende argument, dit argument is leeg en dus oninteressant (=> een argument is een 'flow' uit het vorig commentaarblok
	    }

	    PrefixErrorHandler cerrh(errh, "pattern " + String(argno) + ": ");      // ook deze zetten we klaar voor als het nodig is lijkt mij? want er is hier duidelijk nog geen error momenteel

	    // get slot

        // (het slotwoord is het woord dat 'allow' of 'deny' zegt tegen dat bepaald type stroom)

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
IP6Filter::get_user_viewable_instructions(Element *e, void *)
{
    IP6Filter *ipf = static_cast<IP6Filter *>(e);
    return ipf->instructions.unparse();
}

void
IP6Filter::add_handlers()
{
    add_read_handler("get_program_as_string", get_user_viewable_instructions);
}

void
IP6Filter::push(int, Packet *packet)
{
    this->run(packet);
}

void
IP6Filter::run() {


}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classification)
EXPORT_ELEMENT(IP6Filter)
