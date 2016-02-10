#ifndef CLICK_IP6FILTER_CLASSES_HH
#define CLICK_IP6FILTER_CLASSES_HH

class Primitive {
public:
    String operator_;  
};

class IPHostPrimitive: public Primitive {
public:
    // data
    IP6Address ip6Address;
    String source_or_dest = "not set"; /* will be assigned "src", "dst", "src or dst" or "src and dst" */   

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class IPNetPrimitive: public Primitive {
public:
    // data
    IP6Address ip6NetAddress;
    String source_or_dest = "not set"; /* will be assigned "src", "dst", "src or dst" or "src and dst" */   

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};

class IPVersionPrimitive: public Primitive {
public:
    // data
    uint8_t versionNumber;
    
    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();    
};

class IPDSCPPrimitive: public Primitive {
public:
    // data
    uint32_t dscpValue;

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
}

class IPECNPrimitive: public Primitive {
public:
    // data
    uint32_t ecnValue;

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};

class IPFlowLabelPrimitive: public Primitive {
public:
    // data
    uint8_t flowLabelValuePart1;    /* actually only 4 bits but that does not exist, the 4 most significant bits are set to 0 */
    uint16_t flowLabelValuePart2;

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};

class IPPayloadLengthPrimitive: public Primitive {
public:
    // data
    uint16_t payloadLength;

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};

class IPNextHeaderPrimitive: public Primitive {
public:
    // data
    uint8_t nextHeader;
   
    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};    

class IPHopLimitPrimitive: public Primitive {
public:
    // data
    uint32_t hopLimit;

    void compile(Classification::Wordwise::CompressedProgram& program);
    void print();
};

class EtherHostPrimitive: public Primitive {
public:
    click_ether etherAddress;
    String source_or_dest = "not set"; /* will be assigned "src", "dst", "src or dst" or "src and dst" */   

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class ICMPTypePrimitive: public Primitive {
public:
    uint8_t typeValue;
    
    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class UDPPortPrimitive: public Primitive {
public:
    bool isSourcePort;  /* if false we know it is a Destination port */
    uint16_t port;
};

class TCPPortPrimitive: public Primitive {
public:
    bool isSourcePort;  /* if false we know it is a Source port */
    uint16_t port;
};
