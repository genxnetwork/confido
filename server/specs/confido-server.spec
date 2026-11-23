Name: confido-server
Version: 0.2.0
Release: 1%{?dist}
Summary: Confido Server

License: Apache-2.0
URL: https://github.com/genxnetwork/confido
Source0: LICENSE
Source1: THIRD_PARTY_NOTICES.md
Source2: %{name}-third-party-licenses.tar.gz

%description
Confido Server

%prep

%build

%install
mkdir -p %{buildroot}/usr/local/bin
install -m 0755 %{buildroot}/../../../server/target/release/confido-server %{buildroot}/usr/local/bin/confido-server
install -d %{buildroot}%{_licensedir}/%{name}
install -m 0644 %{SOURCE0} %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/
tar -xzf %{SOURCE2} -C %{buildroot}%{_licensedir}/%{name}/
#mkdir -p %{buildroot}/etc/systemd/system
#install -m 0644 %{buildroot}/../../../server/deployment/systemd-confido.service %{buildroot}/etc/systemd/system/confido.service
#mkdir -p %{buildroot}/usr/share/doc/confido-server
#install -m 0644 %{buildroot}/../../../server/deployment/nginx-confido.conf %{buildroot}/usr/share/doc/confido-server/nginx-confido.conf

%post
#if [ "$1" -eq 1 ] ; then
 # systemctl enable confido.service
 # systemctl daemon-reload
 # systemctl restart confido.service
#fi

%files
%license %{_licensedir}/%{name}
/usr/local/bin/confido-server
#/etc/systemd/system/confido.service
#/usr/share/doc/confido-server/nginx-confido.conf

%changelog
* $(date "+%a %b %d %Y") Grigorii Bezborodov <g.bezborodov@genxnetwork.io> - 1.0.0-1
- Initial RPM release
