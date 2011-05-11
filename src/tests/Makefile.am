AM_CPPFLAGS = -I../ -I../rc_clients
AM_CXXFLAGS = -Wall

noinst_PROGRAMS = resolv spf spool client1 client2 client3 tormoz tormoz2 bbproxy buffers gr

resolv_SOURCES = resolv.cpp ylog.cpp
resolv_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

spf_SOURCES = spf.cpp ../uti.cpp
spf_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

spool_SOURCES = spool.cpp ylog.cpp
spool_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

client1_SOURCES = client1.cpp ylog.cpp
client1_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

client2_SOURCES = client2.cpp ylog.cpp
client2_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

client3_SOURCES = client3.cpp ylog.cpp
client3_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

tormoz_SOURCES = tormoz.cpp ../atormoz.cpp ylog.cpp
tormoz_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

tormoz2_SOURCES = tormoz2.cpp ../atormoz.cpp ../uti.cpp ylog.cpp
tormoz2_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@ -lboost_regex

bbproxy_SOURCES = bbproxy.cpp ylog.cpp
bbproxy_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@ -lboost_regex

buffers_SOURCES = buffers.cpp
buffers_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@

gr_SOURCES = gr.cpp ../rc_clients/greylisting.cpp ../rc_clients/basic_rc_client.cpp \
	../rc.pb.cc ../header_parser.cpp
gr_LDADD = @BOOST_PROGRAM_OPTIONS_LIB@ @BOOST_THREAD_LIB@ @BOOST_SYSTEM_LIB@ $(protobuf_LIBS)