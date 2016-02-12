#include <iostream>
#include "ip6filter_classes.hh"
CLICK_DECLS

using namespace std;
using namespace Classification::Wordwise;

void IPHostPrimitive::print() {
    cout << source_or_destination << " ip host " << ip6Addres << endl; 
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

void IPFlowLabelPrimitive::print() {
    cout << "flow " << flowLabelValuePart2 + (flowLabelValuePart1 << 32) << endl;
}

void IPPayloadLengthPrimitive::print() {
    cout << "plen " << payloadLengthPart1 + payloadLengthPart2 << endl;
}

void IPNextHeaderPrimitive::print() {
    cout << "nxt " << nextHeaderType << endl;
}

void IPHopLimitPrimitive::print() {
    cout << "hlim " << hopLimitValue << endl;
}

void EtherHostPrimitive::print() {
    cout << source_or_dest << " ether host " << etherAddress << endl;
}

void ICMPTypePrimitive::print() {
    cout << "icmp type " << typeValue << endl;
}

void IPHostPrimtive::compile(CompressedProgram& program) {
    if (source_or_destination == SOURCE) {
        program.add_insn(tree, offset_net + 8, ip6Address[0], 0b11111111111111111111111111111111);      // offset_net +8 to +20 contain the source address in an IPv6 packet
        program.add_insn(tree, offset_net + 12, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6Address[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and);
    } else if (_srcdst == DEST) {
        program.add_insn(tree, offset_net + 24, ip6Address[0], 0b11111111111111111111111111111111);      // offset_net +24 to +36 contain the destination address in an IPv6 packet
        program.add_insn(tree, offset_net + 28, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (_srcdst == SOURCE_AND_DEST) {
        program.add_insn(tree, offset_net + 8, ip6Address[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6Address[3], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 24, ip6Address[0], 0b11111111111111111111111111111111);     
        program.add_insn(tree, offset_net + 28, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (_srcdst == SOURCE_OR_DEST) {
        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 8, ip6Address[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6Address[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);

        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 24, ip6Address[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 28, ip6Address[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6Address[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6Address[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);
        
        program.finish_subtree(tree, Classification::c_or);
}

void IPVersionPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, versionNumber, 0b11110000000000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPDSCPPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, versionNumber, 0b00001111110000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPECNPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, dscpValue, 0b00000000001100000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPFlowLabelPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, flowLabelPart1, 0b00000000000000000000000000001111);
    program.add_insn(tree, offset_net + 1, flowLabelPart2, 0b11111111111111110000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

void IPPayloadLengthPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, payloadLength, 0b11111111111111111111111111111111);
    program.finish_subtree(tree, Classification::c_and);
}

void IPNextHeaderPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, nextHeader, 0b00000000000000001111111100000000);
    program.finish_subtree(tree, Classification::c_and);    
}

void IPHopLimitPrimitive::compile(CompressedProgram& program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, nextHeader, 0b00000000000000000000000011111111);
    program.finish_subtree(tree, Classification::c_and);
}

void EtherHostPrimitive::compile(CompressedProgram& program) {
    
}

void UDPPortPrimitive::compile(CompressedProgram& program) {
    
}

void TCPPortPrimitive::compile(CompressedProgram& program) {
    
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classification)
ELEMENT_PROVIDES(FilterClasses)
