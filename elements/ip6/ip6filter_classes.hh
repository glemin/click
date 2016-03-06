#ifndef CLICK_IP6FILTER_CLASSES_HH
#define CLICK_IP6FILTER_CLASSES_HH

#include <stdint.h>
#include <click/glue.hh>
#include <click/vector.hh>
#include <click/string.hh>
#include <clicknet/ether.h>
#include <click/ip6address.hh>
#include <click/etheraddress.hh>
#include "elements/standard/classification.hh"
CLICK_DECLS

class NodeItem {
    
};

class AndItem: public NodeItem {

};

class OrItem: public NodeItem {

};

class TernaryItem: public NodeItem {

};

class Primitive: public NodeItem {
public:
    String operator_;  
};

class IPHostPrimitive: public Primitive {
public:
    // data
    IP6Address ip6Address;
    String source_or_destination; // will be assigned "src", "dst", "src or dst" or "src and dst"

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPNetPrimitive: public Primitive {
public:
    // data
    IP6Address ip6NetAddress;
    String source_or_destination; // will be assigned "src", "dst", "src or dst" or "src and dst"

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPVersionPrimitive: public Primitive {
public:
    // data
    uint8_t versionNumber;
    
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();    
};

class IPDSCPPrimitive: public Primitive {
public:
    // data
    uint32_t dscpValue;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPECNPrimitive: public Primitive {
public:
    // data
    uint32_t ecnValue;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPFlowLabelPrimitive: public Primitive {
public:
    // data
    uint8_t flowLabelValuePart1;    /* actually only 4 bits but that does not exist, the 4 most significant bits are set to 0 */
    uint16_t flowLabelValuePart2;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPPayloadLengthPrimitive: public Primitive {
public:
    // data
    uint16_t payloadLength;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class IPNextHeaderPrimitive: public Primitive {
public:
    // data
    uint8_t nextHeader;
   
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};    

class IPHopLimitPrimitive: public Primitive {
public:
    // data
    uint32_t hopLimit;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class EtherHostPrimitive: public Primitive {
public:
    EtherAddress etherAddress;
    String source_or_destination; //  will be assigned "src", "dst", "src or dst" or "src and dst"

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class ICMPTypePrimitive: public Primitive {
public:
    uint8_t typeValue;
    
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class UDPPortPrimitive: public Primitive {
public:
    bool isSourcePort;  /* if false we know it is a Destination port */
    uint16_t port;

    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class TCPPortPrimitive: public Primitive {
public:
    bool isSourcePort;  /* if false we know it is a Source port */
    uint16_t port;
    
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class TCPOptionPrimitive: public Primitive {
public:
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class NetworkLayerPrimitive: public Primitive {
public:
    int fromWhere;
    int toWhere;
    int valueToMatch;
    
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

class TransportLayerPrimitive: public Primitive {
public:
    int fromWhere;
    int toWhere;
    int valueToMatch;
    
    void compile(Classification::Wordwise::Program& program, Vector<int> tree);
    void print();
};

CLICK_ENDDECLS
#endif
