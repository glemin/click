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
//    const Vector<String> &tokens; //  iet van woorde, wa ne const vector just is, weet ek oek ni direct..., wil da zegge da eens da ge diej initiatlized da er geen elementn ni meer kunne toegeveogd worre of is da toch iet anders..

//    Parser(const Vector<String> &tokens) {
//        this.tokens = tokens;
//    }

    Parser(const Vector<String> &words, Vector<int> &tree, Classification::Wordwise::Program &prog, const Element *context, ErrorHandler *errh) : _words(words), _tree(tree), _program(prog), _context(context), _errh(errh) { }

	enum State {
	    unknown,
	    EXPR0, 
	    EXPR1, 
	    EXPR2,
	    OR_EXPR0, 
	    OR_EXPR1,
	    TERM0, 
	    TERM1, 
	    TERM2,         
        FACTOR0, 
        FACTOR1, 
        FACTOR2,
	    NEGATED_FACTOR0, 
	    NEGATED_FACTOR1, 
	    NEGATED_FACTOR2,
	    
	    // too special shortcut variables
	    FIRST = EXPR0,
	    LAST = NEGATED_FACTOR2
	};

    struct StatePositionPair {                  /* StatePositionPair is a struct inside a struct */
        State state;                              /* state is a state our parser can be in */
	    int position;                       /* position is the where we currently are in reading the _words array */
	};


//	void parse_slot(int output, int pos);   // momenteel ongebruikt maar de functionaliteit zit in parse_program
	int parse();
private:
	const Vector<String> &_words;
	Vector<int> &_tree;
	Classification::Wordwise::Program &_program;
	const Element *_context;
	ErrorHandler *_errh;
	Primitive _prev_prim;

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
