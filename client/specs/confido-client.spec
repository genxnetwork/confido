Name: confido-client
Version: 1.0.0
Release: 1%{?dist}
Summary: Confido Client

License: Proprietary
URL: https://github.com/genxnetwork/confido

%description
Confido Client

%prep

%build

%install
mkdir -p %{buildroot}/usr/local/bin
install -m 0755 %{buildroot}/../../../client/target/release/confido_client %{buildroot}/usr/local/bin/confido-client

%files
/usr/local/bin/confido-client

%changelog
* $(date "+%a %b %d %Y") Grigorii Bezborodov <g.bezborodov@genxnetwork.io> - 1.0.0-1
- Initial RPM release
