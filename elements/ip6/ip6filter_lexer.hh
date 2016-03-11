#ifndef CLICK_IP6FILTER_LEXER_HH
#define CLICK_IP6FILTER_LEXER_HH

#include <stdint.h>
#include <click/glue.hh>
#include <click/element.hh>
#include <click/vector.hh>
#include <click/string.hh>
CLICK_DECLS

namespace click {
namespace ip6filter {

class Lexer {
public:
    Lexer(const char* text);
    Vector<String> lex();
    
private:
    String text;
};

}
}

CLICK_ENDDECLS

#endif
