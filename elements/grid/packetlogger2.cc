#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/ether.h>
#include "packetlogger2.hh"
CLICK_DECLS

PacketLogger2::PacketLogger2()
  : Element(1, 1), _nb(34)
{
  MOD_INC_USE_COUNT;
}

PacketLogger2::~PacketLogger2()
{
  MOD_DEC_USE_COUNT;
}

PacketLogger2 *
PacketLogger2::clone() const
{
  return new PacketLogger2;
}

int
PacketLogger2::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_parse(conf, this, errh,
		  cpKeywords,
		  "NBYTES", cpUnsigned, "number of bytes to record", &_nb,
		  0) < 0) {
    return -1;
  }

  _nb = NBYTES;

  return 0;
}

Packet *
PacketLogger2::simple_action(Packet *p_in)
{
  log_entry d;
  d.timestamp = p_in->timestamp_anno();
  d.length = p_in->length();
  memcpy(d.anno, p_in->all_user_anno(), Packet::USER_ANNO_SIZE);
  memcpy(d.bytes, p_in->data(), _nb < d.length ? _nb : d.length);
  
  _p.push_back(d);

  return p_in;
}

void
PacketLogger2::add_handlers()
{
  add_default_handlers(false);
  add_read_handler("log", print_log, 0);
}

#define MAX_PROC_SIZE  16384
String
PacketLogger2::print_log(Element *e, void *)
{
  PacketLogger2 *p = (PacketLogger2 *) e;

  int bytes_per_entry = 9 + 1 + 9; // 9 digits, '.', 9 digits
  bytes_per_entry += 5;            // " XXXX" (size)
  bytes_per_entry += 4;            // " | "
  bytes_per_entry += 2 * Packet::USER_ANNO_SIZE; 
  bytes_per_entry += 4;            // " | "
  bytes_per_entry += 2 * p->_nb;
  bytes_per_entry += p->_nb / 4;   // ' ' every 4 bytes of data
  bytes_per_entry += 1;            // '\n'
  
  int n = p->_p.size() * bytes_per_entry;
  n = n > MAX_PROC_SIZE ? MAX_PROC_SIZE : n;
  if (n <= 0)
    return "";
  StringAccum sa(n);

  while (p->_p.size() &&
	 sa.length() < MAX_PROC_SIZE - bytes_per_entry) {
    const log_entry &d = p->_p.front();

    sa << d.timestamp;
    char *buf = sa.data() + sa.length();
    int pos = sprintf(buf, " %04u | ", d.length);
    for (int i = 0; i < Packet::USER_ANNO_SIZE; i++) {
      sprintf(buf + pos, "%02x", d.anno[i]);
      pos += 2;
    }
    buf[pos++] = ' ';
    buf[pos++] = '|';
    buf[pos++] = ' ';

    unsigned num_to_print = p->_nb > d.length ? d.length : p->_nb;
    for (unsigned i = 0; i < num_to_print; i++) {
      sprintf(buf + pos, "%02x", d.bytes[i]);
      pos += 2;
      if ((i % 4) == 3) { buf[pos++] = ' '; }
    }
    buf[pos++] = '\n';

    sa.forward(pos);

    p->_p.pop_front();
  }

  return sa.take_string();
}

#include <click/dequeue.cc>
template class DEQueue<PacketLogger2::log_entry>;

CLICK_ENDDECLS
EXPORT_ELEMENT(PacketLogger2)
