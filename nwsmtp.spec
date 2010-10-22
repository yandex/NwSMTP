%define _builddir	.
%define _sourcedir	.
%define _specdir	.
%define _rpmdir		.
%{!?svn_info: %define svn_info %(svn info)}
%{!?revision: %define revision %(svn info|grep 'Last Changed Rev'|awk '{print $NF}')}

Name:		nwsmtp
#Version:	%{yandex_mail_version}
#Release:	%{yandex_mail_release}
Version:	1.0
Release:	%{revision}%{dist}

Summary:	nwsmtp
Group:          System Environment/Daemons
License:        Yandex License
URL:            http://www.yandex.ru
Packager:	Oleg Leksunin <leksunin@yandex-team.ru>

Source0:	etc/nwsmtp.conf
Source1:	nwsmtp.init
Source2:	nwsmtp.sysconfig
Source3:	nwsmtp.cron.d
Source4:	remove_headers.conf
Source5:	etc/ip_param.conf

BuildRequires:	libspf2-devel >= 1.2.9
BuildRequires:	boost >= 1.44.0-0
BuildRequires:	boost-system >= 1.44.0-0
BuildRequires:	boost-thread >= 1.44.0-0
BuildRequires:	boost-program-options >= 1.44.0-0
BuildRequires:	expat-devel >= 1.95.8-8.3

Requires:	libspf2 >= 1.2.9
Requires:	boost >= 1.44.0-0
Requires:	boost-system >= 1.44.0-0
Requires:	boost-thread >= 1.44.0-0
Requires:	boost-program-options >= 1.44.0-0
Requires:	expat >= 1.95.8-8.3
Requires:	pa = 100618-trunk.59007

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)


%description
%{svn_info}


%prep
%{configure} --with-boost-libdir=%{_libdir} --with-blackbox
%{__make} clean


%build
%{__make} %{?_smp_mflags} 


%install
%makeinstall
%{__install} -D -m 644 ./etc/%{SOURCE0} %{buildroot}%{_sysconfdir}/nwsmtp/nwsmtp.conf
%{__install} -D -m 644 ./etc/%{SOURCE4} %{buildroot}%{_sysconfdir}/nwsmtp/remove_headers.conf
%{__install} -D -m 644 ./etc/%{SOURCE5} %{buildroot}%{_sysconfdir}/nwsmtp/ip_param.conf
%{__install} -D -m 755 %{SOURCE1} %{buildroot}%{_initrddir}/nwsmtp
%{__install} -D -m 644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/nwsmtp
%{__install} -D -m 644 %{SOURCE3} %{buildroot}%{_sysconfdir}/cron.d/wd-nwsmtp

%{__mkdir} -p %{buildroot}%{_var}/run/nwsmtp


%pre
getent group nwsmtp >/dev/null || groupadd -r -g 513 nwsmtp
getent passwd nwsmtp >/dev/null || useradd -r -u 513 -g nwsmtp -d /var/run/nwsmtp/ -s /sbin/nologin -c "NWSMTP" nwsmtp
exit 0


%post
if [ $1 = 1 ] ; then
	/sbin/chkconfig --add nwsmtp
	/sbin/service nwsmtp start
elif [ $1 = 2 ] ; then
	/sbin/service nwsmtp restart 
fi
exit 0


%preun
if [ $1 -eq 0 ]; then
        /sbin/service nwsmtp stop
        /sbin/chkconfig --del nwsmtp
fi
exit 0

%clean
%{__rm} -rf %{buildroot}


%files
#%defattr(0644,root,root,0755)
%dir %{_sysconfdir}/nwsmtp
%dir %attr(0755,nwsmtp,nwsmtp) %{_var}/run/nwsmtp
%attr(0644,root,root) %{_sysconfdir}/nwsmtp/nwsmtp.conf
%attr(0644,root,root) %{_sysconfdir}/nwsmtp/remove_headers.conf
%attr(0644,root,root) %{_sysconfdir}/nwsmtp/ip_param.conf
%attr(0755,root,root) %{_sbindir}/nwsmtp
%attr(0755,root,root) %{_initrddir}/nwsmtp
%attr(0644,root,root) %{_sysconfdir}/sysconfig/nwsmtp
%attr(0644,root,root) %{_sysconfdir}/cron.d/wd-nwsmtp


%changelog
* Thu Mar 26 2009 Boris B. Zhmurov <zhmurov@yandex-team.ru>
- initial yandex's rpm build
