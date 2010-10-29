CONFS=ip_param.conf nwsmtp.conf remove_headers.conf virtual_alias_maps

install-data-am:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)/nwsmtp
	$(INSTALL_DATA) $(CONFS) $(DESTDIR)$(sysconfdir)/nwsmtp
