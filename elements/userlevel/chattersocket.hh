#ifndef CHATTERSOCKET_HH
#define CHATTERSOCKET_HH
#include <click/element.hh>
#include <click/error.hh>

/*
=c

ChatterSocket("TCP", PORTNUMBER)
ChatterSocket("UNIX", FILENAME)

=s debugging

reports chatter messages to connected sockets

=io

None

=d

Opens a chatter socket that allows other user-level programs to receive copies
of router chatter traffic. Depending on its configuration string,
ChatterSocket will listen on TCP port PORTNUMBER, or on a UNIX-domain socket
named FILENAME.

The "server" (that is, the ChatterSocket element) simply echoes any messages
generated by the router configuration to any existing "clients". The server
does not read any data from its clients.

When a connection is opened, ChatterSocket responds by stating its protocol
version number with a line like "Click::ChatterSocket/1.0\r\n". The current
version number is 1.0.

ChatterSocket broadcasts copies of messages generated by the default
ErrorHandler or the C<click_chatter> function. Most elements report messages
or run-time errors using one of these mechanisms.

=e

  ChatterSocket(unix, /tmp/clicksocket);

=a ControlSocket */

class ChatterSocket : public Element { public:

  ChatterSocket();
  ~ChatterSocket();

  const char *class_name() const	{ return "ChatterSocket"; }
  ChatterSocket *clone() const		{ return new ChatterSocket; }
  
  int configure(const Vector<String> &conf, ErrorHandler *);
  int initialize(ErrorHandler *);
  void uninitialize();

  void selected(int);

  void handle_text(ErrorHandler::Seriousness, const String &);
  void write_chatter();
  
 private:

  String _unix_pathname;
  int _socket_fd;
  
  Vector<String> _messages;
  Vector<uint32_t> _message_pos;
  uint32_t _max_pos;
  
  Vector<int> _fd_alive;
  Vector<uint32_t> _fd_pos;
  int _live_fds;

  static const char *protocol_version;

  int write_chatter(int fd, int min_useful_message);

};

inline void
ChatterSocket::handle_text(ErrorHandler::Seriousness, const String &message)
{
  if (_live_fds && message.length()) {
    _messages.push_back(message);
    _message_pos.push_back(_max_pos);
    _max_pos += message.length();
    write_chatter();
  }
}

#endif
