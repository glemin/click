#ifndef CLICK_IP6FILTER_CLASSES_HH
#define CLICK_IP6FILTER_CLASSES_HH

class IPHostPrimitive: public Primitive {
public:
    // data
    IP6Address ip6Address;
    int source_or_destination; /* will be assigned an enumerate type as an acronym for a certain option */   

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class IPVersionPrimitive: public Primitive {
public:
    // data
    uint32_t versionNumber;
    
    void compile(Classification::Wordwise::CompressedProgram program);
    void print();    
};

class IPDSCPPrimitive: public Primitive {
public:
    // data
    uint32_t dscpValue;

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
}

class IPECNPrimitive: public Primitive {
public:
    // data
    uint32_t ecnValue;

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class IPFlowLabelPrimitive: public Primitive {
public:
    // data
    uint32_t flowLabelValuePart1;
    uint32_t flowLabelValuePart2;

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class IPPayloadLengthPrimitive: public Primitive {
public:
    // data
    uint32_t payloadLengthPart1;
    uint32_t payloadLengthPart2;

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};

class IPNextHeaderPrimitive: public Primitive {
public:
    // data
    uint32_t nextHeaderType;
   
    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};    

class IPHopLimitPrimitive: public Primitive {
public:
    // data
    uint32_t hopLimit;

    void compile(Classification::Wordwise::CompressedProgram program);
    void print();
};
