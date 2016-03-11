#include "ip6filter_lexer.hh"
CLICK_DECLS

namespace click {
namespace ip6filter {

Lexer::Lexer(String text) {
    this->text = text;
}


List<String> Lexer::lex() {
    int currentPositionInText = 0;
    Vector<String> tokenList;
    String token = "";  // We build a token from the ground up.

    while (pos < text.length()) {
        if (!((text[currentPositionInText] == ' ') || (text[currentPositionInText] == '\t') || (text[currentPositionInText] == '\n') || (text[currentPositionInText] == '\v') || (text[currentPositionInText] == '\f') || (text[currentPositionInText] == '\r'))) {
            currentToken += text[currentPositionInText];
        } else {
            if (currentToken != "") {   // at least one non-space or non-tab character was read
                tokenList.push_back(currentToken);
            }
            currentToken = "";
        }
        currentPositionInText++;
    }
   
    for(int i = 0; i < tokenList.size(); i++) {
        printf("String waarde # %i is gelijk aan %s", i, tokenList);
    }
   
    return tokenList;
}

}
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(Lexer)
