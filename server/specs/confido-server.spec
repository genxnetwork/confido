Name: confido-server
Version: 1.0.0
Release: 1%{?dist}
Summary: Confido Server

License: Proprietary
URL: https://github.com/genxnetwork/confido

%description
Confido Server

%prep

%build

%install
mkdir -p %{buildroot}/usr/local/bin
install -m 0755 ./confido-server %{buildroot}/usr/local/bin/confido-server
mkdir -p %{buildroot}/etc/systemd/system
install -m 0644 ./deployment/systemd-confido.service %{buildroot}/etc/systemd/system/confido.service

%post
if [ \$1 -eq 1 ] ; then
  systemctl enable confido.service
  systemctl daemon-reload
  systemctl restart confido.service
fi

%files
/usr/local/bin/confido-server
/etc/systemd/system/confido.service

%changelog
* $(date "+%a %b %d %Y") Grigorii Bezborodov <g.bezborodov@genxnetwork.io> - 1.0.0-1
- Initial RPM release
