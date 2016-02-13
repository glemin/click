#ifndef CLICK_IP6FILTER_PARSER_HH
#define CLICK_IP6FILTER_PARSER_HH

#include <stdint.h>
#include <click/glue.hh>
#include <click/element.hh>
#include <click/vector.hh>
#include <click/string.hh>
#include "elements/standard/classification.hh"
CLICK_DECLS

class Parser { // ne parser zeker, mor wat diej doe is nog ni zu duidelijk
public:
    const Vector<String> &_words; //  iet van woorde, wa ne const vector just is, weet ek oek ni direct..., wil da zegge da eens da ge diej initiatlized da er geen elementn ni meer kunne toegeveogd worre of is da toch iet anders..
    Vector<int> &_tree; // ne vagen boom der oek nog tusse, deze keer blijkbaar ni const
    Classification::Wordwise::Program &_program;       // dit is diej low level brol van hierboven!! das hetzelfde als _zprog !!
    const Element* _context;        // een element wordt hier een context genoemd => not sure why :d
    ErrorHandler* _errh;
    Primitive _prev_prim;           // Waarom hebben we die prev prim nodig?????? EEEn wat happens when it is the first, is this then 0???? or so oo mthing eeelsee ..

    Parser(const Vector<String> &words, Vector<int> &tree, Classification::Wordwise::Program &program, const Element *context, ErrorHandler *errh) 
    : _words(words), _tree(tree), _program(program), _context(context), _errh(errh) { } /* set all variables in the constructor */

    struct ParseState {                  /* ParseState is a struct inside a struct */
        int stateNumber;
	    int lastPosition;
	    ParseState(int givenStateNumber) : stateNumber(givenStateNumber) { } /* constructor does set state variable with : syntax, does nothing else */
	};
	enum {      // s stands for state, or for statement
	    s_expr0, s_expr1, s_expr2,          // These names are being used to give a name to all states in the push-down automata.
	    s_orexpr0, s_orexpr1,               // As well as being used as Stack symbols that can be pushed on the stack or consumed.
	    s_term0, s_term1, s_term2,          // If the stack empties, we arrive in a final state and the parsing has ended.
        s_factor0, s_factor1, s_factor2,    // For more information on this topic view "Introduction to automata theory, languages and computation".
	    s_factor0_neg, s_factor1_neg, s_factor2_neg // A book written by Hopcroft, Motwani and Ullman.
	};

//	void parse_slot(int output, int pos);   // momenteel ongebruikt maar de functionaliteit zit in parse_program
	int parse_expr_iterative(int pos);
	int parse_primitive(int parsePosition, bool negatedSignSeenBeforePrimitive, Classification::Wordwise::Program& compileIntoThisProgram);  // functie die de functionaliteit bevat om tests te parsen, een test is: true, false, quals data of quals relop data
};

/* We check whether the given words adhere to the given syntax below and while doing that compile the expressions.

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
 
 Primitives themselves are again walked through, and are compiled on the fly.
 */
 
CLICK_ENDDECLS
#endif
