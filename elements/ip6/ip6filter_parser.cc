#include "ip6filter_parser.hh"

using Classification::Wordwise::Program;

int
IP6Filter::Parser::parse_primitive(int position, bool negatedSignSeenBeforePrimitive, Program& compileIntoThisProgram)    // parse het test gedeelte uit de grammatica
{
//    constexpr int pos = position;
    currentWord = _words[position];
    

    // error handling
    if (position >= _words.size())
	    return position;    /* out of range */
	if (_words[position] == ")" || _words[position] == "||" || _words[position] == "?" || _words[position] == ":" || _words[position] == "or" )
	    return position;    /* non-acceptable first word */
	  
	// start of parsing
	if (_words[position] == "true") {
	    _program.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (negatedSignSeenBeforePrimitive)
	        _program.negate_subtree(_tree);
	    return position + 1;    /* go further in parse_expr_iterative() with the next position */
	}
	if (_words[position] == "false") {
	    _program.add_insn(_tree, 0, 0, 0);  /* everything matches with mask 0 */
	    if (!negatedSignSeenBeforePrimitive)               
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
                primitive->compile(compileIntoThisProgram);
               
                return position + 4;
            } else {            
                primitive = new IPVersionPrimitive();
                primitive->operator_ = "==";
                primitive->versionNumber = atoll([position+2].c_str());    /* no error handling we might want to use boost::lexical_cast */
                primitive->compile(compileIntoThisProgram);
                
                return position + 3;
            }
        } else if (_words[position+1] == "dscp") {
           if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {    /* determine whether an optional ==, >, >=, <=, <, != keyword was used */
                primitive = new IPDSCPPrimitive();
                primitive->operator_ = _words[position+2];
                primitive->dscpValue = atoll([position+3].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPDSCPPrimitive();
                primitive->operator_ = "==";
                primitive->dscpValue = atoll([position+2].c_str());
                primitive->compile(compileIntoThisProgram);
                
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
                primitive->compile(compileIntoThisProgram);
	        
                return position + 4;
            } else {
                primitive = new IPFlowLabelPrimitive();
                primitive->operator_ = "==";
                primitive->flowLabelValue1 = atoll(_words[position+2].c_str());
                primitive->flowLabelValue2 = atoll(_words[position+2].c_str()) >> 16;
                primitive->compile(compileIntoThisProgram);
                
                return position + 3;        
            }
        } else if (_words[position+1] == "plen") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPPayloadLengthPrimitive();
                primitive->operator_ =_words[position+2];
                primitive->payloadLength = atoll(_words[position+3].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPPayloadLengthPrimitive();
                primitive->operator_ = "==";
                primitive->payloadLength = atoll(_words[position+2].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 3;
            }
        } else if (_words[position+1] == "nxt") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPNextHeaderPrimitive();
                primitive->operator_ == _words[position+2];
                primitive->nextHeader = atoll(_words[position+3].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPNextHeaderPrimitive();
                primitive->operator_ = "==";
                primitive->nextHeader = atoll(_words[position+2].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 3;
            }
        } else if (_words[position+1] == "hlim") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPHopLimitPrimitive();
                primitive->operator_ = _words[position+2];
                primitive->hopLimit = atoll(_words[position+3].c_str());
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPHopLimitPrimitive();
                primitive->operator_ = "==";
                primitive->hopLimit = atoll(_words[position+2].c_str());
                primitive->compile(compileIntoThisProgram);
                
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
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive->operator_ = "==";
                primitive->ip6Address = IP6AddressArg().parse(_words[position+2], 0b11111111111111111111111111111111 , _context);
                primitive->compile(compileIntoThisProgram);
                
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
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPNetPrimitive();
                primitive->operator_ == "==";
                
                if(!IP6PrefixArg().parse(_words[position+2], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */

                primitive->compile(compileIntoThisProgram);
                
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
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPHostPrimitive();
                primitive->operator_ = "==";
                if(!IP6AddressArg().parse(_words[position+2], primitive->ip6Address, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->primitiveOperator = _words[position+2];
                primitive->compile(compileIntoThisProgram);
                
                return position + 3;                
            }
        } else if (_words[position+1] == "net") {
            if (_words[position+2] == "==" || _words[position+2] == ">" || _words[position+2] == ">=" || _words[position+2] == "<=" || _words[position+2] == "<" 
            || _words[position+2] == "!=") {
                primitive = new IPNetPrimitive(compileIntoThisProgram);
                primitive->operator_ = _words[position+2];
                
                if(!IP6PrefixArg().parse(_words[position+3], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
            } else {
                primitive = new IPNetPrimitive(compileIntoThisProgram);
                primitive->operator_ = "==";
                if(!IP6PrefixArg().parse(_words[position+2], primitive->ip6NetAddress, 0b11111111111111111111111111111111 , _context))
                    return -10; /* parsing failed */
                primitive->compile(compileIntoThisProgram);
                
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
                primitive->compile(compileIntoThisProgram);
                
                return position + 4;
                
            
        }
	}
	
    if (negatedSignSeen)
        _program.negate_subtree(_tree);

    return position;
}
