#include "ip6filter_lexer.hh"

using namespace click::ip6filter;

Lexer::Lexer(const char* text) {
    this->text = text;
}


List<String> Lexer::lex() {
    Vector<String> tokenList;
    
    int pos = 0;
    
    String currentToken = "";
    while (pos < text.length()) {
        if (!(text[pos] == ' ')) {      // TODO also allow tabs
            currentToken += s[pos];
        } else {
            if (currentToken != "") {   // at least one non-space character was read
                tokenList.push_back(currentToken);
            }
            currentToken = "";
        }
        pos++;
    }
   
    for(int i = 0; i < tokenList.size(); i++) {
        printf("String waarde # %i is gelijk aan %s", i, tokenList);
    }
   
    return tokenList;
}
