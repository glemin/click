#include <click/config.h>
#include <click/args.hh>
#include <click/vector.hh>
#include <click/error.hh>
#include "ip6filter_classes.hh"
#include "ip6filter_parser.hh"
#include <stack>
#include <iostream>
CLICK_DECLS

using Classification::Wordwise::Program;
using std::stack;
using namespace std;

int Parser::parse_primitive(int position, bool negatedSignSeenBeforePrimitive, Program& compileIntoThisProgram) {

//    constexpr int pos = position;
//    int currentWord = _words[position];
    
    // error handling
    if (position >= _words.size())
	    return position;    /* out of range */
	if (_words[position] == ")" || _words[position] == "||" || _words[position] == "?" || _words[position] == ":" || _words[position] == "or" )
	    return position;    /* non-acceptable first word */
	  
	// start of parsing
	if (_words[position] == "true") {
	    compileIntoThisProgram.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (negatedSignSeenBeforePrimitive)
	        compileIntoThisProgram.negate_subtree(_tree);
	    return position + 1;    /* go further in parse_expr_iterative() with the next position */
	}
	if (_words[position] == "false") {
	    compileIntoThisProgram.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (!negatedSignSeenBeforePrimitive)               
	        compileIntoThisProgram.negate_subtree(_tree);
	    return position + 1;    /* go further in parse_expr_iterative() with the next position */
	}


    if (!(position + 1 <= _words.size())) { /* all qualifiers are followed by at least some data */
        // throw error + return
        return -10; /* -10 ook nog veranderen */
    }
  
    if (_words[position] == "ip") {

        if (_words[position+1] == "vers") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */
                IPVersionPrimitive primitive;
                primitive.operator_ = _words[position+2];
                primitive.versionNumber = atoll(_words[position+3].c_str());    /* no error handling we might want to use boost::lexical_cast */
                primitive.compile(compileIntoThisProgram, _tree);
               
                return position + 4;
            } else {            
                IPVersionPrimitive primitive;
                primitive.operator_ = "==";
                primitive.versionNumber = atoll(_words[position+2].c_str());    /* no error handling we might want to use boost::lexical_cast */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else if (_words[position+1] == "dscp") {
           if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */
                IPDSCPPrimitive primitive;
                primitive.operator_ = _words[position+2];
                primitive.dscpValue = atoll(_words[position+3].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                IPDSCPPrimitive primitive;
                primitive.operator_ = "==";
                primitive.dscpValue = atoll(_words[position+2].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else if (_words[position+1] == "ce") {
        
        } else if (_words[position+1] == "ect") {
        
        } else if (_words[position+1] == "flow") {
           if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */    
                IPFlowLabelPrimitive primitive;
                primitive.operator_ = _words[position+2];
                primitive.flowLabelValuePart1 = atoll(_words[position+3].c_str()) >> 16;
                primitive.flowLabelValuePart2 = atoll(_words[position+3].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
	        
                return position + 4;
            } else {
                IPFlowLabelPrimitive primitive;
                primitive.operator_ = "==";
                primitive.flowLabelValuePart1 = atoll(_words[position+2].c_str()) >> 16;
                primitive.flowLabelValuePart2 = atoll(_words[position+2].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;        
            }
        } else if (_words[position+1] == "plen") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                IPPayloadLengthPrimitive primitive;
                primitive.operator_ =_words[position+2];
                primitive.payloadLength = atoll(_words[position+3].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                IPPayloadLengthPrimitive primitive;
                primitive.operator_ = "==";
                primitive.payloadLength = atoll(_words[position+2].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else if (_words[position+1] == "nxt") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                IPNextHeaderPrimitive primitive;
                primitive.operator_ == _words[position+2];
                primitive.nextHeader = atoll(_words[position+3].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                IPNextHeaderPrimitive primitive;
                primitive.operator_ = "==";
                primitive.nextHeader = atoll(_words[position+2].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else if (_words[position+1] == "hlim") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                IPHopLimitPrimitive primitive;
                primitive.operator_ = _words[position+2];
                primitive.hopLimit = atoll(_words[position+3].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                IPHopLimitPrimitive primitive;
                primitive.operator_ = "==";
                primitive.hopLimit = atoll(_words[position+2].c_str());
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else {
            /* an error occured: throw an error and return */
            return -10;
        } 
    } else if (_words[position] == "src") {  /* this must be followed by host or net keyword */
        if (_words[position+1] == "host") {
            IPHostPrimitive primitive;
            primitive.source_or_destination = "src";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive.operator_ = _words[position+3];
                
                ArgContext argContext;  // gives more details about the error when something goes wrong
                if(!IP6AddressArg().parse(_words[position+3], primitive.ip6Address, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                primitive.operator_ = "==";
                
                ArgContext argContext;  // gives more details about the error when something goes wrong
                if(!IP6AddressArg().parse(_words[position+2], primitive.ip6Address, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                cout << "we gaan returnen" << endl;
                return position + 3;
            }
        } else if (_words[position+1] == "net") {
            IPNetPrimitive primitive;
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive.operator_ = _words[position+2];
                
                ArgContext argContext;  // gives more details about the error when something goes wrong
                int resultPrefixLength;
                if(!IP6PrefixArg().parse(_words[position+3], primitive.ip6NetAddress, resultPrefixLength, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                primitive.operator_ == "==";
                
                ArgContext argContext;
                int resultPrefixLength;
                if(!IP6PrefixArg().parse(_words[position+2], primitive.ip6NetAddress, resultPrefixLength, argContext))
                    return -10; /* parsing failed */

                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else if (_words[position+1] == "ether" && _words[position+2] == "host") {
            if (_words[position+3] == "==" || _words[position+3] == ">" || _words[position+3] == ">=" || _words[position+3] == "<=" || _words[position+3] == "<" 
            || _words[position+3] == "!=") {
                EtherHostPrimitive primitive;
                
//              if(!EtherAddressArg()            
            
            } else {
            
            }
        } else {
            // throw error + return
            return -10; /* -10 ook nog veranderen */
        }
	    
    } else if (_words[position] == "dst") {  /* this must be followed by host or net keyword */
        if (_words[position+1] == "host") {
            IPHostPrimitive primitive;
            primitive.source_or_destination = "dst";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive.operator_ == _words[position+2];
                
                ArgContext argContext;
                if(!IP6AddressArg().parse(_words[position+3], primitive.ip6Address, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                primitive.operator_ = "==";
                
                ArgContext argContext;
                if(!IP6AddressArg().parse(_words[position+2], primitive.ip6Address, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;                
            }
        } else if (_words[position+1] == "net") {
            IPNetPrimitive primitive;
            primitive.source_or_destination = "dst";
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive.operator_ = _words[position+2];
                
                ArgContext argContext;
                int resultPrefixLength;
                if(!IP6PrefixArg().parse(_words[position+3], primitive.ip6NetAddress, resultPrefixLength, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            } else {
                primitive.operator_ = "==";
                
                ArgContext argContext;
                int resultPrefixLength;
                if(!IP6PrefixArg().parse(_words[position+2], primitive.ip6NetAddress, resultPrefixLength, argContext))
                    return -10; /* parsing failed */
                primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 3;
            }
        } else {
            // throw error + return
            return -10; /* -10 ook nog veranderen */
        }    
	} else if (_words[position] == "ether") {    // wellicht 'ether host'
        if (_words[position+1] == "host") {
            EtherHostPrimitive primitive;
            primitive.source_or_destination = "src or dst";
            
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive.operator_ = _words[position+2];
  //              if(!EtherAddressArg().parse(_words[position+3], primitive.etherAddress, _context)) {
  //                  return -10; /* parsing failed */
   //             }
  //              primitive.compile(compileIntoThisProgram, _tree);
                
                return position + 4;
            }
            
        }
	} else {
	    // throw error + return
	    return -10; /* -10 ook nog veranderen */
	}
	
    if (negatedSignSeenBeforePrimitive) /* staat dit juist ? returnen we niet te vroeg bij de meeste van de if-then-else branches ? */
        compileIntoThisProgram.negate_subtree(_tree);

    return position;
}

// Remark: This position variable given as a parameter is actually used and updated along the way in this function. However, since it is not passed by reference it will not change upon returning.

// TODO seems like we work with a pushdown automata here => we use the version that accepts when emptying the parseStack (cfr. Introduction to automata theory, languages and computation by Hopcroft, Motwani and Ullman).

// zo'n pushdown automaat is in essentie een niet-deterministische eindige automaat met epsilon transities toegestaan en 1 bijkomstige eigenschap: een parseStack waarop het een string van "stack symbolen" kan opslaan.

/* We parse the following grammar:

 * expr ::= orexpr                      // start subtree    & end with finish_subtree(tree, Classification::c_ternary)
 *	|   orexpr ? expr : expr
 * orexpr ::= orexpr || orexpr          // start subtree    & end with finish_subtree(tree, Classification::c_or)
 *	|   orexpr or orexpr
 *	|   term
 * term ::= term && term                // start subtree    & end with finish_subtree(tree, Classification::c_and)
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
 
int Parser::parse_expr_iterative(int pos) { 
    Vector<ParseState> stk;
    stk.push_back(ParseState(s_expr0));

    while (stk.size()) {
	ParseState &ps = stk.back();    /* look at top of stack */
	int new_state = -1;

	switch (ps.state) {
	case s_expr0:
	    cout << "s_expr0" << endl;
	    _program.start_subtree(_tree);
	    ps.state = s_expr1;
	    new_state = s_orexpr0;
	    break;
	case s_expr1:
	    cout << "s_expr1" << endl;
	    if (pos >= _words.size() || _words[pos] != "?")
		goto finish_expr;
	    ++pos;
	    ps.state = s_expr2;
	    new_state = s_expr0;
	    break;
	case s_expr2:
	    cout << "s_expr2" << endl;
	    if (pos == ps.lastPosition || pos >= _words.size() || _words[pos] != ":") {
		_errh->error("missing %<:%> in ternary expression");
		goto finish_expr;
	    }
	    ++pos;
	    ps.state = s_expr1;
	    new_state = s_orexpr0;
	    break;
	finish_expr:
	    cout << "finish normal expression" << endl;
	    _program.finish_subtree(_tree, Classification::c_ternary);
	    break;

	case s_orexpr0:
	    cout << "s_orexpr0" << endl;
	    _program.start_subtree(_tree);
	    ps.state = s_orexpr1;
	    new_state = s_term0;
	    break;
	case s_orexpr1:
	    cout << "s_orexpr1" << endl;
	    if (pos >= _words.size() || (_words[pos] != "or" && _words[pos] != "||"))
		goto finish_orexpr;
	    ++pos;
	    new_state = s_term0;
	    break;
	finish_orexpr:
	    cout << "finish or-expression" << endl;
	    _program.finish_subtree(_tree, Classification::c_or);
	    break;

	case s_term0:
	    cout << "s_term0" << endl;
	    _program.start_subtree(_tree);
	    ps.state = s_term1;
	    new_state = s_factor0;
	    break;
	case s_term1:
	case s_term2:
	    cout << "s_term1 (or s_term2) | don't know which one" << endl;
	    if (pos == ps.lastPosition) {
		if (ps.state == s_term1)
		    _errh->error("missing expression");
		goto finish_term;
	    }
	    if (pos < _words.size() && (_words[pos] == "and" || _words[pos] == "&&")) {
		ps.state = s_term1;
		++pos;
	    } else
		ps.state = s_term2;
	    new_state = s_factor0;
	    break;
	finish_term:
	    cout << "finish term" << endl;
	    _program.finish_subtree(_tree);
	    break;

	case s_factor0:
	case s_factor0_neg:
	    cout << "s_factor0 (or s_factor0_neg) | don't know which one" << endl;	
	    if (pos < _words.size() && (_words[pos] == "not" || _words[pos] == "!")) {
		ps.state += (s_factor1 - s_factor0);
		new_state = (ps.state == s_factor1 ? s_factor0_neg : s_factor0);
		++pos;
	    } else if (pos < _words.size() && _words[pos] == "(") {
		ps.state += (s_factor2 - s_factor0);
		new_state = s_expr0;
		++pos;
	    } else
		pos = parse_primitive(pos, ps.state == s_factor0_neg, _program);
	    break;
	case s_factor1:
	case s_factor1_neg:
	    cout << "s_factor1 (or s_factor1_neg) | don't know which one" << endl;	
	    if (pos == ps.lastPosition)
		_errh->error("missing expression after %<%s%>", _words[pos - 1].c_str());
	    break;
	case s_factor2:
	case s_factor2_neg:
	    cout << "s_factor2 (or s_factor2_neg) | don't know which one" << endl;	
	    if (pos == ps.lastPosition)
		_errh->error("missing expression after %<(%>");
	    if (pos < _words.size() && _words[pos] == ")")
		++pos;
	    else if (pos != ps.lastPosition)
		_errh->error("missing %<)%>");
	    if (ps.state == s_factor2_neg)
		_program.negate_subtree(_tree);
	    break;
	}

	if (new_state >= 0) {
	    ps.lastPosition = pos;
	    stk.push_back(ParseState(new_state));
	} else
	    stk.pop_back();
    }

    return pos;
}
 
// TODO trace maken voor een voorbeeld (de stappen std::cout'en)
/*
int Parser::parse_expr_iterative(int position) {
    stack<ParseState> parseStack;
    parseStack.push(ParseState(s_expr0));

    while (parseStack.size()) {
	    ParseState &parseState = parseStack.pop();
	    int newStackSymbol = -1; // -1 means epsilon in the 'Introduction to automata theory' book

    	switch (parseState.stateNumber) { // tells in which state we are
            case s_expr0:                           // TODO enkel bij s_expr0 start men en subtree, bij de overige twee s_expr's niet
	            _program.start_subtree(_tree);      // whenever you start a subtree this means that you are setting up a new &&, ? or || construct or the like              
	            parseState.stateNumber = s_expr1;                 // TODO dit is de volgende staat die je moet uitproberen als het niet matcht denk ik, bij 0 kan 't nooit matchen denk ik
	            newStackSymbol = s_orexpr0;     // this on the other hand is the new symbol that needs to be pushed on the stack (and has nothing to do with the state we are in) ; if the stack gets empty we need are finished.
	            break;
        	case s_expr1:
	            if (position >= _words.size() || _words[position] != "?")
		            goto finish_expr;               // TODO mss is dit als je merkt dat het blijkbaar geen expressie met een ? is, dus wandel je verder en probeer je iets anders, je finisht dit gedeelte en wandelt dus naar de vlgende mogelijkheid, een s_orexpr0 :p
	            ++position;      // Attention: the position variable (defaulted at 1) gets increased here.
	            parseState.stateNumber = s_expr2;                 // TODO dit is de volgende staat die je moet uitproberen als het niet matcht denk ik
	            newStackSymbol = s_expr0;
	            break;
	        case s_expr2:
	            if (position == parseState.lastPosition || position >= _words.size() || _words[position] != ":") {
		            _errh->error("missing %<:%> in ternary expression");
		            goto finish_expr;
	            }
	            ++position;      // Attention: the position variable (defaulted at 1) gets increased here.
	            parseState.stateNumber = s_expr1;                 // TODO is dit wel de volgende staat die je moet proberen als 't niet matcht?? hmmn :o
	            newStackSymbol = s_orexpr0;
	            break;

	            finish_expr:
	                _program.finish_subtree(_tree, Classification::c_ternary);         // TODO enkel bij s_expr2 beindigt men de subtree, bij de overige twee s_expr's niet
	                break;                                                          // TODO dit is ternary want er staat 'orexpr ? expr : expr'

	        case s_orexpr0:                         // TODO enkel bij s_orexpr0 start men een subtree, bij de andere s_orexpr niet
	            _program.start_subtree(_tree);          // Let's start an OR subtree
	            parseState.stateNumber = s_orexpr1;
	            newStackSymbol = s_term0;
	            break;
	        case s_orexpr1:
	            if (position >= _words.size() || (_words[position] != "or" && _words[position] != "||"))
		            goto finish_orexpr;
	            ++position;
	            newStackSymbol = s_term0;
	            break;

	            finish_orexpr:
	                _program.finish_subtree(_tree, Classification::c_or);          // TODO enkel bij s_orexpr1 beeindigt men de subtree, bij de andere s_orexpr niet
	                break;

	        case s_term0:
	            _program.start_subtree(_tree);          // Let's start an AND subtree
	            parseState.stateNumber = s_term1;
	            newStackSymbol = s_factor0;
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
	            newStackSymbol = s_factor0;
	            break;

	            finish_term:
	                _program.finish_subtree(_tree);    // The default value is Classification::c_and I believe.
	            break;

	        case s_factor0:
	        case s_factor0_neg:
	            if (position < _words.size() && (_words[position] == "not" || _words[position] == "!")) {
		            parseState.stateNumber += (s_factor1 - s_factor0);
	    	        newStackSymbol = (parseState.stateNumber == s_factor1 ? s_factor0_neg : s_factor0); // TODO if we where in s_factor1 we go to s_factor0_neg, if we ere in s_factor1_neg we go to s_factor_0 I suppose
	    	        ++position;
	            } else if (position < _words.size() && _words[position] == "(") {
		            parseState.stateNumber += (s_factor2 - s_factor0);  // if you started in negative you stay negative? 
		            newStackSymbol = s_expr0;       // a new expression can occur when we arrived at factor
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

	    if (newStackSymbol >= 0) {       // if we got a stack symbol we push it onto the stack
	        parseState.lastPosition = position;
	        parseStack.push(ParseState(newStackSymbol));
	    } else                      // if we didn't got a stack symbol we pull a symbol from the stack
	        parseStack.pop();   // maybe this is a backtrack
    }

    return position;
}
*/

CLICK_ENDDECLS
ELEMENT_PROVIDES(Parser)
