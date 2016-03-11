#include <click/config.h>
#include <iostream>
#include "ip6filter_classes.hh"
CLICK_DECLS

using namespace std;
using namespace Classification::Wordwise;

namespace click {
namespace ip6filter {

enum {  /* temporarily */
    // if you change this, change click-fastclassifier.cc also
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

void IPHostPrimitive::print() {
    cout << source_or_destination << " ip host " << ip6Address << endl; 
}

void IPVersionPrimitive::print() {
    cout << "ip vers " << versionNumber << endl;
}

void IPDSCPPrimitive::print() {
    cout << "dscp " << dscpValue << endl;
}

void IPECNPrimitive::print() {
    cout << "ecn " << ecnValue << endl;
}

// GCC gives
// ../elements/ip6/ip6filter_classes.cc:26:70: warning: left shift count >= width of type [enabled by default]
//  cout << "flow " << flowLabelValuePart2 + (flowLabelValuePart1 << 32) << endl;
void IPFlowLabelPrimitive::print() {
    cout << "flow " << flowLabelValuePart2 + (flowLabelValuePart1 << 32) << endl;
}



void IPPayloadLengthPrimitive::print() {
    cout << "plen " << payloadLength << endl;
}

void IPNextHeaderPrimitive::print() {
    cout << "nxt " << nextHeader << endl;
}

void IPHopLimitPrimitive::print() {
    cout << "hlim " << hopLimit << endl;
}

void EtherHostPrimitive::print() {
    cout << source_or_destination << " ether host " << etherAddress << endl;
}

void ICMPTypePrimitive::print() {
    cout << "icmp type " << typeValue << endl;
}

void IPHostPrimitive::compile(Program& program, Vector<int> tree) {
    cout << "c0" << endl;
    if (source_or_destination == "src") {
        cout << "c1" << endl;
        program.add_insn(tree, offset_net + 8, ip6Address.data32()[0], 0b11111111111111111111111111111111);      // offset_net +8 to +20 contain the source address in an IPv6 packet
        cout << "c2" << endl;
        program.add_insn(tree, offset_net + 12, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        cout << "c3" << endl,
        program.add_insn(tree, offset_net + 20, ip6Address.data32()[3], 0b11111111111111111111111111111111);
        cout << "c4" << endl;

        program.finish_subtree(tree, Classification::c_and);
        cout << "c5" << endl;
    } else if (source_or_destination == "dst") {
        cout << "c6" << endl;
        program.add_insn(tree, offset_net + 24, ip6Address.data32()[0], 0b11111111111111111111111111111111);      // offset_net +24 to +36 contain the destination address in an IPv6 packet
        program.add_insn(tree, offset_net + 28, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address.data32()[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (source_or_destination == "src and dst") {
        program.add_insn(tree, offset_net + 8, ip6Address.data32()[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6Address.data32()[3], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 24, ip6Address.data32()[0], 0b11111111111111111111111111111111);     
        program.add_insn(tree, offset_net + 28, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address.data32()[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (source_or_destination == "src or dst") {
        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 8, ip6Address.data32()[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6Address.data32()[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);

        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 24, ip6Address.data32()[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 28, ip6Address.data32()[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address.data32()[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address.data32()[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);
        
        program.finish_subtree(tree, Classification::c_or);
    } else {
        // error
    }
}

void IPNetPrimitive::compile(Program& program, Vector<int> tree) {

}

void IPVersionPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, versionNumber, 0b11110000000000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPDSCPPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, dscpValue, 0b00001111110000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPECNPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, ecnValue, 0b00000000001100000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPFlowLabelPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, flowLabelValuePart1, 0b00000000000000000000000000001111);
    program.add_insn(tree, offset_net + 1, flowLabelValuePart2, 0b11111111111111110000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPPayloadLengthPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, payloadLength, 0b11111111111111111111111111111111);
    program.finish_subtree(tree, Classification::c_and);
}

void IPNextHeaderPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, nextHeader, 0b00000000000000001111111100000000);
    program.finish_subtree(tree, Classification::c_and);    
}

void IPHopLimitPrimitive::compile(Program& program, Vector<int> tree) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, hopLimit, 0b00000000000000000000000011111111);
    program.finish_subtree(tree, Classification::c_and);
}

void EtherHostPrimitive::compile(Program& program, Vector<int> tree) {
    
}

void UDPPortPrimitive::compile(Program& program, Vector<int> tree) {
    
}

void TCPPortPrimitive::compile(Program& program, Vector<int> tree) {
    
}

}
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classification)
ELEMENT_PROVIDES(FilterClasses)
