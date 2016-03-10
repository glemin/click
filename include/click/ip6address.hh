// -*- related-file-name: "../../lib/ip6address.cc" -*-
#ifndef CLICK_IP6ADDRESS_HH
#define CLICK_IP6ADDRESS_HH
#include <click/string.hh>
#include <clicknet/ip6.h>
#include <click/ipaddress.hh>
#include <click/etheraddress.hh>
CLICK_DECLS

class IP6Address { public:

    typedef uninitialized_type uninitialized_t;

    /** @brief Construct a zero-valued IP6Address (equal to ::). */
    inline IP6Address() {
	memset(&_addr, 0, sizeof(_addr));
    }

    /** @brief Construct an IP6Address from a sixteen-byte buffer. */
    explicit inline IP6Address(const unsigned char *x) {
	memcpy(&_addr, x, sizeof(_addr));
    }

    /** @brief Construct an IPv4-Mappped IP6Address (RFC 4291-2.5.5.2)
     *
     * The address has format ::FFFF:@a x. */
    explicit inline IP6Address(IPAddress x) {
	*this = x;		// This is a pointer to a IP6Address class, if we dereference it we get the class itself.
    }

    /** @brief Construct an IP6Address from a human-readable string. */
    explicit IP6Address(const String &x);		// "fec0:0:0:1::1"

    /** @brief Construct an IP6Address from an in6_addr */

    /*
     * The in6_addr struct from #include <linux/in6.h> looks like this:
     *
     * struct in6_addr {
     *          unsigned char   s6_addr[16];    // IPv6 address
     *      };
     */
    explicit inline IP6Address(const struct in6_addr &x)
	: _addr(x) {
    }

    /** @brief Construct an IPv4-Mapped IP6Address from an in_addr */
    explicit inline IP6Address(const struct in_addr &x) {
	*this = x;
    }

    /** @brief Construct an uninitialized IP6Address. */
    // The regular constructor assigns to our variables a default value (i.e. it initializes them). This constructor can be used if you don't want that to happen and
    // as such save some memory. This constructor asks as its single argument a dummy struct of type unitialiazed_type which is a struct without methods or variables.
    // The only reason this dummy struct needs to be passed is to let the compiler now that we want to use the uninitialized version of the constructor and not the
    // regular one that initializes our variables.

    inline IP6Address(const uninitialized_type &dummy __attribute__((unused))) {
    	// __attribute__((unused))) is a GNU compiler specific feature that indicates that variable dummy is unused (if not indicated, it would generate a warning).
    }


    /** @brief Return an IP6Address equal to the prefix mask of length @a
     * prefix_len.
     * @param prefix_len prefix length; 0 <= @a prefix_len <= 128
     *
     * For example, make_prefix(0) is ::, make_prefix(12) is fff0::, and
     * make_prefix(128) is ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff.  Causes an
     * assertion failure if @a prefix_len is out of range.
     *
     * @sa mask_to_prefix_len, make_inverted_prefix */
    static IP6Address make_prefix(int prefix_len);

    /** @brief Return an IP6Address equal to the inversion of make_prefix(@a
     * prefix_len).
     * @param prefix_len prefix length; 0 <= @a prefix_len <= 128
     * @return ~make_prefix(@a prefix_len)
     * @sa make_prefix */
    static IP6Address make_inverted_prefix(int prefix_len);

    typedef uint32_t (IP6Address::*unspecified_bool_type)() const; // TODO wth is this???
    inline operator unspecified_bool_type() const;

    operator const struct in6_addr &() const	{ return _addr; }
    operator struct in6_addr &()			{ return _addr; }
    const struct in6_addr &in6_addr() const	{ return _addr;	}
    struct in6_addr &in6_addr()			{ return _addr;	}

    unsigned char *data()			{ return &_addr.s6_addr[0]; }
    const unsigned char *data() const		{ return &_addr.s6_addr[0]; }
    uint16_t *data16()				{ return (uint16_t *)&_addr.s6_addr[0]; }
    const uint16_t *data16() const		{ return (uint16_t *)&_addr.s6_addr[0]; }
    uint32_t *data32()				{ return (uint32_t *)&_addr.s6_addr[0]; }
    const uint32_t *data32() const		{ return (uint32_t *)&_addr.s6_addr[0]; }

    inline uint32_t hashcode() const;

    int mask_to_prefix_len() const;
    inline bool matches_prefix(const IP6Address &addr, const IP6Address &mask) const;
    inline bool mask_as_specific(const IP6Address &) const;

    /** @brief Test if this address contains an embedded Ethernet address.
     *
     * An IPv6 address with embedded Ethernet address has format
     * "nnnn:nnnn:nnnn:nnnn:uuvv:wwFF:FExx:yyzz", where the embedded Ethernet
     * address is "uu-vv-ww-xx-yy-zz". */
    bool has_ether_address() const {
	return _addr.s6_addr[11] == 0xFF && _addr.s6_addr[12] == 0xFE;
    }

    /** @brief Extract embedded Ethernet address into @a x.
     * @param[out] x Ethernet address
     * @return true iff has_ether_address() */
    bool ether_address(EtherAddress &x) const;

    /** @brief Return true iff the address is a IPv4-compatible address.
     * NOTE: This form has been deprecated in RFC 4291 (2.5.5.1)
     *
     * An IPv4-mapped address has format "::w:x:y:z", where the
     * IPv4 address is "w.x.y.z". */
    inline bool is_ip4_compatible() const {
	return data32()[0] == 0 && data32()[1] == 0		// first 3 of 4 bytes need to be 0 then (as you can see here)
	    && data32()[2] == 0;                        // on the last byte, byte 3 we don't need to test anything because
    }                                               // this byte  is allowed to be anything and contains the actual IPv4 address.

    /** @brief Return true iff the address is a IPv4-mapped address.
     *
     * An IPv4-mapped address has format "::FFFF:w:x:y:z", where the
     * embedded IPv4 address is "w.x.y.z". */
    inline bool is_ip4_mapped() const {
	return data32()[0] == 0 && data32()[1] == 0     // here the third byte (byte 2) needs to contain FFFF and and the fourth
	    && data32()[2] == htonl(0x0000FFFFU);       // byte (byte 3) is again allowed to be anything.
    }

    /** @brief Return true iff the address is a multicast address
     * s6_addr[0] = 0xff;
     *
     */
    inline bool is_multicast() const {
        return _addr.s6_addr[0] == 0xff;            // in IPv6 we have multicase if the first byte (byte 0), contains the value 0xFF
    }

    /** @brief Return true iff the address is a link-local address.
     * fe80::/64
     *
     */
    inline bool is_link_local() const {
        return data32()[0] == htonl(0xfe800000) && data32()[1] == 0;
    }

    /** @brief Return IPv4-mapped address.
     *
     * @return non-empty IPv4 address iff is_ip4_mapped() is
     *  true. IPAddress() otherwise */
    IPAddress ip4_address() const;

    // bool operator==(const IP6Address &, const IP6Address &);
    // bool operator!=(const IP6Address &, const IP6Address &);

    // IP6Address operator&(const IP6Address &, const IP6Address &);
    // IP6Address operator|(const IP6Address &, const IP6Address &);
    // IP6Address operator~(const IP6Address &);

    inline IP6Address &operator&=(const IP6Address &);
    inline IP6Address &operator&=(const struct in6_addr &);
    inline IP6Address &operator|=(const IP6Address &);
    inline IP6Address &operator|=(const struct in6_addr &);

    inline IP6Address &operator=(const struct in6_addr &);
    inline IP6Address &operator=(const struct in_addr &);

    void unparse(StringAccum &sa) const;
    String unparse() const;
    String unparse_expanded() const;

    String s() const			{ return unparse(); }
    inline operator String() const CLICK_DEPRECATED;

    typedef const IP6Address &parameter_type;

  private:

    struct in6_addr _addr;  // TODO waarom heeft men daar nog eens struct voorgetypt? Is in6_addr van zichzelf al geen struct?

};

inline
IP6Address::operator unspecified_bool_type() const
{
    const uint32_t *ai = data32();
    return ai[0] || ai[1] || ai[2] || ai[3] ? &IP6Address::hashcode : 0;
}

inline
IP6Address::operator String() const
{
    return unparse();
}

inline bool
operator==(const IP6Address &a, const IP6Address &b)
{
    const uint32_t *ai = a.data32(), *bi = b.data32();
    return ai[0] == bi[0] && ai[1] == bi[1] && ai[2] == bi[2] && ai[3] == bi[3];
}

inline bool
operator!=(const IP6Address &a, const IP6Address &b)
{
    const uint32_t *ai = a.data32(), *bi = b.data32();
    return ai[0] != bi[0] || ai[1] != bi[1] || ai[2] != bi[2] || ai[3] != bi[3];
}

inline StringAccum &
operator<<(StringAccum &sa, const IP6Address &a) {
    a.unparse(sa);
    return sa;
}

inline bool
IP6Address::matches_prefix(const IP6Address &addr, const IP6Address &mask) const  // TODO wat doen die addr en mask hier??
{
    const uint32_t *xi = data32(), *ai = addr.data32(), *mi = mask.data32();
    return ((xi[0] ^ ai[0]) & mi[0]) == 0						  // if xi and ai differ, then mi needs to be zero, if xi and ai are equal we don't care about mi's value
	&& ((xi[1] ^ ai[1]) & mi[1]) == 0
	&& ((xi[2] ^ ai[2]) & mi[2]) == 0
	&& ((xi[3] ^ ai[3]) & mi[3]) == 0;
}

inline bool
IP6Address::mask_as_specific(const IP6Address &mask) const						// TODO wat is dit???
{
    const uint32_t *xi = data32(), *mi = mask.data32();
    return ((xi[0] & mi[0]) == mi[0] && (xi[1] & mi[1]) == mi[1]
	    && (xi[2] & mi[2]) == mi[2] && (xi[3] & mi[3]) == mi[3]);
}

inline IP6Address &
IP6Address::operator&=(const IP6Address &x)						// we &= every byte
{
    uint32_t *ai = data32();
    const uint32_t *bi = x.data32();
    ai[0] &= bi[0];
    ai[1] &= bi[1];
    ai[2] &= bi[2];
    ai[3] &= bi[3];
    return *this;
}

inline IP6Address &
IP6Address::operator&=(const struct in6_addr &x)				// we &= every byte
{
    uint32_t *ai = data32();
    const uint32_t *bi = (uint32_t *)&x.s6_addr[0];
    ai[0] &= bi[0];
    ai[1] &= bi[1];
    ai[2] &= bi[2];
    ai[3] &= bi[3];
    return *this;
}

inline IP6Address &
IP6Address::operator|=(const IP6Address &x)						// we |= every byte
{
    uint32_t *ai = data32();
    const uint32_t *bi = x.data32();
    ai[0] |= bi[0];
    ai[1] |= bi[1];
    ai[2] |= bi[2];
    ai[3] |= bi[3];
    return *this;
}

inline IP6Address &
IP6Address::operator|=(const struct in6_addr &x)				// we |= every byte
{
    uint32_t *ai = data32();
    const uint32_t *bi = (uint32_t *)&x.s6_addr;
    ai[0] |= bi[0];
    ai[1] |= bi[1];
    ai[2] |= bi[2];
    ai[3] |= bi[3];
    return *this;
}

inline IP6Address
operator&(const IP6Address &a, const IP6Address &b)				// we & every byte between those two distinct IP6addresses
{
    const uint32_t *ai = a.data32(), *bi = b.data32();
    IP6Address result = IP6Address::uninitialized_t();
    uint32_t *ri = result.data32();
    ri[0] = ai[0] & bi[0];
    ri[1] = ai[1] & bi[1];
    ri[2] = ai[2] & bi[2];
    ri[3] = ai[3] & bi[3];
    return result;
}

inline IP6Address
operator&(const struct in6_addr &a, const IP6Address &b)		// we & every byte between those two distinct IP6addresses
{
    const uint32_t *ai = (const uint32_t *)&a.s6_addr[0], *bi = b.data32();
    IP6Address result = IP6Address::uninitialized_t();
    uint32_t *ri = result.data32();
    ri[0] = ai[0] & bi[0];
    ri[1] = ai[1] & bi[1];
    ri[2] = ai[2] & bi[2];
    ri[3] = ai[3] & bi[3];
    return result;
}

inline IP6Address
operator|(const IP6Address &a, const IP6Address &b)				// we | every byte between those two distinct IP6addresses
{
    const uint32_t *ai = a.data32(), *bi = b.data32();
    IP6Address result = IP6Address::uninitialized_t();
    uint32_t *ri = result.data32();
    ri[0] = ai[0] | bi[0];
    ri[1] = ai[1] | bi[1];
    ri[2] = ai[2] | bi[2];
    ri[3] = ai[3] | bi[3];
    return result;
}

inline IP6Address
operator~(const IP6Address &x)									// we ~ every byte
{
    const uint32_t *ai = x.data32();
    IP6Address result = IP6Address::uninitialized_t();
    uint32_t *ri = result.data32();
    ri[0] = ~ai[0];
    ri[1] = ~ai[1];
    ri[2] = ~ai[2];
    ri[3] = ~ai[3];
    return result;
}

inline IP6Address &
IP6Address::operator=(const struct in6_addr &a)					// we assign a in6_addr to this class
{																// TODO waarom staat er weer struct in6_addr, omvat het type in6_addr zelf al niet dat het om een struct gaat?
    _addr = a;													// TODO mag je dat er dan nog zo maar voorschrijven? Btw, nu is het zelfs een const struct, wat doet die const daar
    return *this;												// TODO ook nog is?
}

inline IP6Address &
IP6Address::operator=(const struct in_addr &a)					// we assign a in_addr (which contains an IPv4 address) to this class
{
    memset(&_addr, 0, 10);										// we set the first 10 bytes to zero
    data16()[5] = 0xffff;										// we set the 6th 2-byte pair of the total of 8 pairs to FFFF
    data32()[3] = a.s_addr;										// we put the IPv4 address in the last byte (= byte 3)
    return *this;
}

inline uint32_t													// TODO wth is dit allemaal?? waarvoor gebruiken we het?? be shiften wat in de 3de byte zit allemaal 1 naar links
IP6Address::hashcode() const									// TODO om daarna de 4de bit bij op te tellen?? waarom doen we dit allemaal??
{
    return (data32()[2] << 1) + data32()[3];
}

/** @class IP6AddressArg
  @brief Parser class for IPv6 addresses. */
struct IP6AddressArg {
    static const char *basic_parse(const String &str, IP6Address &result,
				   const ArgContext &args = blank_args);
    static bool parse(const String &str, IP6Address &result,
		      const ArgContext &args = blank_args);
    static bool parse(const String &str, struct in6_addr &result,
		      const ArgContext &args = blank_args) {
        return parse(str, reinterpret_cast<IP6Address &>(result), args);
    }

};

/** @class IP6PrefixArg
  @brief Parser class for IPv6 address prefixes. */
class IP6PrefixArg { public:
    IP6PrefixArg(bool allow_bare_address_ = false)
	: allow_bare_address(allow_bare_address_) {
    }
    bool parse(const String &str, IP6Address &addr, int &prefix_len,
	       const ArgContext &args = blank_args) const;
    bool parse(const String &str, IP6Address &addr, IP6Address &prefix,
	       const ArgContext &args = blank_args) const;
    bool parse(const String &str, struct in6_addr &addr, struct in6_addr &prefix,
	       const ArgContext &args = blank_args) const {
        return parse(str, reinterpret_cast<IP6Address &>(addr),
                     reinterpret_cast<IP6Address &>(prefix), args);
    }
    bool allow_bare_address;
};

template<> struct DefaultArg<IP6Address> : public IP6AddressArg {};
template<> struct DefaultArg<struct in6_addr> : public IP6AddressArg {};
template<> struct has_trivial_copy<IP6Address> : public true_type {};

CLICK_ENDDECLS
#endif
