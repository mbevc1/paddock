# Built by scripts/build-rpm.sh from a prebuilt static binary; nothing is compiled here.
%global debug_package %{nil}
%{!?owner: %global owner owner}

Name:           paddock
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Hosting panel for isolated PHP vhosts
License:        MPL-2.0
URL:            https://github.com/%{owner}/paddock
Source0:        paddock-%{version}.tar.gz
Source1:        paddock.sysusers
ExclusiveArch:  x86_64 aarch64

BuildRequires:  systemd-rpm-macros
Requires:       httpd
Requires:       mod_ssl
Requires:       mod_md
Requires:       mariadb-server
Requires:       fail2ban
Requires:       nftables
Requires:       xfsprogs
Requires:       policycoreutils-python-utils
Requires:       openssh-server
%{?sysusers_requires_compat}

%description
Paddock runs PHP sites on AlmaLinux in vhosts that cannot
see or touch each other's files or processes. A root agent changes the host; a
web panel, running unprivileged, drives it. Run "paddock setup" after
installing to configure the host.

%prep
%setup -q -n paddock-%{version}

%build

%install
install -D -m 0755 paddock %{buildroot}%{_bindir}/paddock
for unit in paddock-agent.service paddock-web.service paddock-nft.service paddock-httpd@.service; do
    install -D -m 0644 deploy/systemd/$unit %{buildroot}%{_unitdir}/$unit
done
install -D -m 0644 deploy/sysusers.d/paddock.conf %{buildroot}%{_sysusersdir}/paddock.conf
install -D -m 0644 deploy/tmpfiles.d/paddock.conf %{buildroot}%{_tmpfilesdir}/paddock.conf
(cd deploy && find etc -type f) | while read -r f; do
    install -D -m 0644 "deploy/$f" "%{buildroot}%{_datadir}/paddock/$f"
done
install -d -m 0755 %{buildroot}/var/lib/paddock
install -d -m 0700 %{buildroot}/var/lib/paddock/agent
install -d -m 0700 %{buildroot}/var/lib/paddock/web

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post paddock-agent.service paddock-web.service paddock-nft.service
%tmpfiles_create %{_tmpfilesdir}/paddock.conf

%preun
%systemd_preun paddock-agent.service paddock-web.service paddock-nft.service

%postun
%systemd_postun_with_restart paddock-agent.service paddock-web.service

%files
%license LICENSE
%doc README.md
%{_bindir}/paddock
%{_unitdir}/paddock-agent.service
%{_unitdir}/paddock-web.service
%{_unitdir}/paddock-nft.service
%{_unitdir}/paddock-httpd@.service
%{_sysusersdir}/paddock.conf
%{_tmpfilesdir}/paddock.conf
%{_datadir}/paddock
%dir %attr(0755,root,root) /var/lib/paddock
%dir %attr(0700,root,root) /var/lib/paddock/agent
%dir %attr(0700,paddock,paddock) /var/lib/paddock/web

%changelog
* Tue Nov 17 2026 Paddock maintainers - %{version}-%{release}
- Package the paddock binary, units, sysusers, tmpfiles and default host configs.
