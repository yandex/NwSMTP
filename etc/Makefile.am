CONFS=ip_param.conf remove_headers.conf greylisting.conf

install-data-am:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/nwsmtp
	$(INSTALL_DATA) $(CONFS) $(DESTDIR)$(sysconfdir)/nwsmtp
