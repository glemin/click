#include <iostream>
#include "ip6filter_classes.hh"

using namespace std;
using namespace Classification::Wordwise;

IPHostPrimitive::print() {
    cout << source_or_destination << " ip host " << ip6Addres << endl; 
}

IPVersionPrimitive::print() {
    cout << "ip vers " << versionNumber << endl;
}

IPDSCPPrimitive::print() {
    cout << "dscp " << dscpValue << endl;
}

IPECNPrimitive::print() {
    cout << "ecn " << ecnValue << endl;
}

IPFlowLabelPrimitive::print() {
    cout << "flow " << flowLabelValuePart2 + (flowLabelValuePart1 << 32) << endl;
}

IPPayloadLengthPrimitive::print() {
    cout << "plen " << payloadLengthPart1 + payloadLengthPart2 << endl;
}

IPNextHeaderPrimitive::print() {
    cout << "nxt " << nextHeaderType << endl;
}

IPHopLimitPrimitive::print() {
    cout << "hlim " << hopLimitValue << endl;
}

IPHostPrimtive::compile(CompressedProgram program) {
    if (source_or_destination == SOURCE) {
        program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);      // offset_net +8 to +20 contain the source address in an IPv6 packet
        program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and);
    } else if (_srcdst == DEST) {
        program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);      // offset_net +24 to +36 contain the destination address in an IPv6 packet
        program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (_srcdst == SOURCE_AND_DEST) {
        program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);     
        program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);

        program.finish_subtree(tree, Classification::c_and); 
    } else if (_srcdst == SOURCE_OR_DEST) {
        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 8, ip6AddressArray[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 12, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 16, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 20, ip6AddressArray[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);

        program.start_subtree(tree);
        program.add_insn(tree, offset_net + 24, ip6AddressArray[0], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 28, ip6AddressArray[1], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 32, ip6AddressArray[2], 0b11111111111111111111111111111111);
        program.add_insn(tree, offset_net + 36, ip6AddressArray[3], 0b11111111111111111111111111111111);
        program.finish_subtree(tree, Classification::c_and);
        
        program.finish_subtree(tree, Classification::c_or);
}

IPVersionPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, versionNumber, 0b11110000000000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

IPDSCPPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, versionNumber, 0b00001111110000000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

IPECNPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, dscpValue, 0b00000000001100000000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

IPFlowLabelPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net, flowLabelPart1, 0b00000000000000000000000000001111);
    program.add_insn(tree, offset_net + 1, flowLabelPart2, 0b11111111111111110000000000000000);
    program.finish_subtree(tree, Classification::c_and);
}

IPPayloadLengthPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, payloadLength, 0b11111111111111111111111111111111);
    program.finish_subtree(tree, Classification::c_and);
}

IPNextHeaderPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, nextHeader, 0b00000000000000001111111100000000);
    program.finish_subtree(tree, Classification::c_and);    
}

IPHopLimitPrimitive::compile(CompressedProgram program) {
    program.start_subtree(tree);
    program.add_insn(tree, offset_net + 1, nextHeader, 0b00000000000000000000000011111111);
    program.finish_subtree(tree, Classification::c_and);
}
