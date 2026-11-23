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

%post
#if [ "$1" -eq 1 ] ; then
 # systemctl enable confido.service
 # systemctl daemon-reload
 # systemctl restart confido.service
#fi

%files
%license %{_licensedir}/%{name}
/usr/local/bin/confido-server

%changelog
* $(date "+%a %b %d %Y") Grigorii Bezborodov <g.bezborodov@genxnetwork.io> - 1.0.0-1
- Initial RPM release
