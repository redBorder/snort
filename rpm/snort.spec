%global debug_package %{nil}

# Other useful bits
%define SnortRulesDir %{_sysconfdir}/snort/rules
%define noShell /bin/false

# Handle the options noted above.
# Default of no openAppId, but --with openappid will enable it
%define openappid 0
%{?_with_openappid:%define openappid 1}

%define vendor Snort.org
%define for_distro RPMs
%define release 1
%define realname snort

%if %{openappid}
  %define EnableOpenAppId --enable-open-appid
%endif

%if %{openappid}
Name: %{realname}-openappid
Version: 2.9.8.3
Summary: An open source Network Intrusion Detection System (NIDS) with open AppId support
Conflicts: %{realname}
%else
Name: %{realname}
Version: 2.9.8.3
Summary: An open source Network Intrusion Detection System (NIDS)
Conflicts: %{realname}-openappid
%endif
Epoch: 1
Release: %{release}
Group: Applications/Internet
License: GPL
Url: http://www.snort.org/
Source0: %{realname}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Packager: Official Snort.org %{for_distro}
Vendor: %{vendor}
BuildRequires: autoconf, automake, pcre-devel, libpcap-devel, libdnet-devel, libs3-devel, libxml2-devel, libtirpc-devel

%description
Snort is an open source network intrusion detection system, capable of
performing real-time traffic analysis and packet logging on IP networks.
It can perform protocol analysis, content searching/matching and can be
used to detect a variety of attacks and probes, such as buffer overflows,
stealth port scans, CGI attacks, SMB probes, OS fingerprinting attempts,
and much more.

Snort has three primary uses. It can be used as a straight packet sniffer
like tcpdump(1), a packet logger (useful for network traffic debugging,
etc), or as a full blown network intrusion detection system. 

You MUST edit /etc/snort/snort.conf to configure snort before it will work!

Please see the documentation in %{_docdir}/%{realname}-%{version} for more
information on snort features and configuration.

%prep
%setup -q -n %{realname}-%{version}

%build
CFLAGS="$RPM_OPT_FLAGS"
export AM_CFLAGS="-g -O2"
SNORT_BASE_CONFIG="--prefix=%{_prefix} --sbindir=%{_sbindir} --exec-prefix=%{_prefix} --with-libpcap-includes=/usr/include \
                   --with-libpcap-libraries=/usr/lib --with-libpfring-includes=/usr/include \
                   --with-libpfring-libraries=/usr/lib --enable-perfprofiling --enable-normalizer \
                   --enable-mpls --enable-targetbased --enable-ppm --enable-active-response --enable-reload \
                   --enable-react --enable-flexresp3 --with-daq-libraries=/usr/local/lib \
                   --with-daq-includes=/usr/local/include --enable-control-socket --enable-gdb \
                   --enable-reputationgeoip --enable-shared-rep --enable-extradata-file \
                   --enable-file-inspect --with-libs3-includes=/usr/include --with-libs3-libraries=/usr/lib64 --enable-remote-file-s3"

./configure $SNORT_BASE_CONFIG %{?EnableOpenAppId}
make

%install
InstallSnort() {
   %__rm -rf $RPM_BUILD_ROOT
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sbindir}
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_bindir}
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/snort
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_var}/log/snort
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_initrddir}
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_mandir}/man8
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version}
   %__mkdir_p -p $RPM_BUILD_ROOT/usr/lib/systemd/system/
   %__install -p -m 0755 src/%{realname} $RPM_BUILD_ROOT%{_sbindir}/%{realname}
   %__install -p -m 0755 tools/control/snort_control $RPM_BUILD_ROOT%{_bindir}/snort_control
   %__install -p -m 0755 tools/u2spewfoo/u2spewfoo $RPM_BUILD_ROOT%{_bindir}/u2spewfoo
   %__install -p -m 0755 tools/u2boat/u2boat $RPM_BUILD_ROOT%{_bindir}/u2boat
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine
   %__mkdir_p -m 0755 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor
   %__install -p -m 0755 src/dynamic-plugins/sf_engine/.libs/libsf_engine.so.0 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine
   %__ln_s -f %{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.so.0 $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.so
   %__install -p -m 0755 src/dynamic-preprocessors/build%{_prefix}/lib/snort_dynamicpreprocessor/*.so* $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor
   	
   for file in $RPM_BUILD_ROOT%{_libdir}/%{realname}-%{version}_dynamicpreprocessor/*.so;  do  
          	preprocessor=`basename $file`
   	%__ln_s -f %{_libdir}/%{realname}-%{version}_dynamicpreprocessor/$preprocessor.0 $file     
   done   
   	
   %__install -p -m 0644 snort.8 $RPM_BUILD_ROOT%{_mandir}/man8
   %__rm -rf $RPM_BUILD_ROOT%{_mandir}/man8/snort.8.gz
   %__gzip $RPM_BUILD_ROOT%{_mandir}/man8/snort.8
   %__install -p -m 0755 rpm/snortd $RPM_BUILD_ROOT%{_initrddir}
   %__install -p -m 0644 rpm/snort.sysconfig $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{realname}
   %__install -p -m 0644 rpm/snort.logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/snort
   %__install -p -m 0644 rpm/snortd.service $RPM_BUILD_ROOT/usr/lib/systemd/system/snortd.service
   find doc -maxdepth 1 -type f -not -name 'Makefile*' -exec %__install -p -m 0644 {} $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version} \;
   
   %__rm -f $RPM_BUILD_ROOT%{_docdir}/%{realname}-%{version}/Makefile.*

   if [ "$1" = "openappid" ]; then
	%__install -p -m 0755 tools/u2openappid/u2openappid $RPM_BUILD_ROOT%{_bindir}/u2openappid
        # This isn't built, it has to be copied from the source tree
	%__install -p -m 0755 tools/appid_detector_builder.sh $RPM_BUILD_ROOT%{_bindir}/appid_detector_builder.sh
   fi
}

# Fix the RULE_PATH
%__sed -e 's;var RULE_PATH ../rules;var RULE_PATH %{SnortRulesDir};' \
	< etc/snort.conf > etc/snort.conf.new
%__rm -f etc/snort.conf
%__mv etc/snort.conf.new etc/snort.conf

# Fix dynamic-preproc paths
%__sed -e 's;dynamicpreprocessor directory \/usr\/local/lib\/snort_dynamicpreprocessor;dynamicpreprocessor directory %{_libdir}\/%{realname}-%{version}_dynamicpreprocessor;' < etc/snort.conf > etc/snort.conf.new
%__rm -f etc/snort.conf
%__mv etc/snort.conf.new etc/snort.conf

# Fix dynamic-engine paths
%__sed -e 's;dynamicengine \/usr\/local/lib\/snort_dynamicengine;dynamicengine %{_libdir}\/%{realname}-%{version}_dynamicengine;' < etc/snort.conf > etc/snort.conf.new
%__rm -f etc/snort.conf
%__mv etc/snort.conf.new etc/snort.conf

%if %{openappid}
  InstallSnort openappid
%else
  InstallSnort plain
%endif

%clean
%__rm -rf $RPM_BUILD_ROOT


%pre
# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	/usr/sbin/groupadd snort 2> /dev/null || true
	/usr/sbin/useradd -M -d %{_var}/log/snort -s %{noShell} -c "Snort" -g snort snort 2>/dev/null || true
fi

%post
## Make a symlink if there is no link for snort-plain
#%if %{openappid}
#  if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then \
#    %__rm -f %{_sbindir}/snort; %__ln_s %{_sbindir}/%{name} %{_sbindir}/snort; fi
#%else
#  if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then \
#    %__rm -f %{_sbindir}/snort; %__ln_s %{_sbindir}/%{name}-plain %{_sbindir}/snort; fi
#%endif

# We should restart it to activate the new binary if it was upgraded
%{_initrddir}/snortd condrestart 1>/dev/null 2>/dev/null

# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	%__chown -R snort.snort %{_var}/log/snort
	/sbin/chkconfig --add snortd
fi


%preun
if [ $1 = 0 ] ; then
	# We get errors about not running, but we don't care
	%{_initrddir}/snortd stop 2>/dev/null 1>/dev/null
	/sbin/chkconfig --del snortd
fi

%postun
# Try and restart, but don't bail if it fails
if [ $1 -ge 1 ] ; then
	%{_initrddir}/snortd condrestart  1>/dev/null 2>/dev/null || :
fi

# Only do this if we are actually removing snort
if [ $1 = 0 ] ; then
	if [ -L %{_sbindir}/snort ]; then
		%__rm -f %{_sbindir}/snort
	fi

	/usr/sbin/userdel snort 2>/dev/null
fi
systemctl daemon-reload

%files
%defattr(-,root,root)
%if %{openappid}
%attr(0755,root,root) %{_sbindir}/%{name}
%attr(0755,root,root) %{_bindir}/u2openappid
%attr(0755,root,root) %{_bindir}/appid_detector_builder.sh
%else
%attr(0755,root,root) %{_sbindir}/%{name}
%endif
%attr(0755,root,root) %{_bindir}/snort_control
%attr(0755,root,root) %{_bindir}/u2spewfoo
%attr(0755,root,root) %{_bindir}/u2boat
%attr(0644,root,root) %{_mandir}/man8/snort.8.*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/logrotate.d/snort
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/snort
%attr(0755,root,root) %config(noreplace) %{_initrddir}/snortd
%attr(0755,snort,snort) %dir %{_var}/log/snort
%attr(0755,root,root) %dir %{_sysconfdir}/snort
%attr(0644,root,root) %{_docdir}/%{realname}-%{version}/*
%attr(0755,root,root) %dir %{_libdir}/%{realname}-%{version}_dynamicengine
%attr(0755,root,root) %{_libdir}/%{realname}-%{version}_dynamicengine/libsf_engine.*
%attr(0755,root,root) %dir %{_libdir}/%{realname}-%{version}_dynamicpreprocessor
%attr(0755,root,root) %{_libdir}/%{realname}-%{version}_dynamicpreprocessor/libsf_*_preproc.*
%attr(0644,root,root) /usr/lib/systemd/system/snortd.service

%dir %{_docdir}/%{realname}-%{version}
%docdir %{_docdir}/%{realname}-%{version}

%changelog
* Wed Nov 08 2023 David Vanhoucke <dvanhoucke@redborder.com> - 2.9.0-1
- Created snort rpm for redborder
