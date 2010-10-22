AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src src/tests etc

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

distclean-local:
	-$(RM) ./aminclude.am

