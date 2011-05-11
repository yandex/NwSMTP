AM_CPPFLAGS=-I$(top_srcdir)
AM_CXXFLAGS=-Wall
sbin_PROGRAMS = nwsmtp

protocol_headers = rc.pb.h
protocol_sources = rc.pb.cc

nwsmtp_CFLAGS=@EXPAT_CFLAGS@
nwsmtp_CPPFLAGS=@BOOST_CPPFLAGS@ $(protobuf_CFLAGS)
nwsmtp_LDFLAGS=@BOOST_LDFLAGS@ @EXPAT_LDFLAGS@ $(protobuf_LIBS)
nwsmtp_LDADD=-lexpat -lopendkim @BOOST_PROGRAM_OPTIONS_LIB@\
	@BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@
nwsmtp_SOURCES = $(protocol_sources) main.cpp options.cpp server.cpp \
	smtp_connection.cpp log.cpp switchcfg.cpp smtp_connection_manager.cpp\
	rbl.cpp envelope.cpp rfc_date.cpp uti.cpp bb_client_rcpt.cpp http_client.cpp bb_parser.cpp\
	so_client.cpp avir_client.cpp aliases.cpp smtp_client.cpp pidfile.cpp timer.cpp\
	param_parser.cpp header_parser.cpp ip_options.cpp rfc822date.c atormoz.cpp adkim.cpp\
	 auth.cpp bb_client_auth.cpp smtp_connection_auth.cpp bb_client_mailfrom.cpp\
	smtp_connection_mailfrom.cpp rc_clients/basic_rc_client.cpp\
	rc_clients/greylisting.cpp

CLEANFILES = $(protocol_headers) $(protocol_sources)

.proto.pb.cc :
	$(AM_V_GEN)$(PROTOC) $(PROTOC_ARGS) $<

.proto.pb.h :
	$(AM_V_GEN)$(PROTOC) $(PROTOC_ARGS) $<

SUFFIXES = .proto .pb.cc

PROTOC = protoc
PROTOC_ARGS = -I. --cpp_out=.
