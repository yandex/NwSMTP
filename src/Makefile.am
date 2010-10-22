AM_CPPFLAGS=-I$(top_srcdir)
AM_CXXFLAGS=-Wall
sbin_PROGRAMS = nwsmtp

nwsmtp_CFLAGS=@EXPAT_CFLAGS@
nwsmtp_CPPFLAGS=@BOOST_CPPFLAGS@
nwsmtp_LDFLAGS=@BOOST_LDFLAGS@ @EXPAT_LDFLAGS@
nwsmtp_LDADD=-lexpat -lopendkim @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@
nwsmtp_SOURCES = main.cpp options.cpp server.cpp \
	smtp_connection.cpp log.cpp switchcfg.cpp smtp_connection_manager.cpp\
	rbl.cpp envelope.cpp rfc_date.cpp uti.cpp bb_client_rcpt.cpp http_client.cpp bb_parser.cpp\
	so_client.cpp avir_client.cpp aliases.cpp smtp_client.cpp pidfile.cpp timer.cpp param_parser.cpp\
	eom_parser.cpp header_parser.cpp ip_options.cpp rfc822date.c atormoz.cpp adkim.cpp auth.cpp\
	bb_client_auth.cpp smtp_connection_auth.cpp
