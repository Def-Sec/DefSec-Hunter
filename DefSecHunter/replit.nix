{pkgs}: {
  deps = [
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.libffi
    pkgs.openssl
    pkgs.cacert
    pkgs.libyaml
  ];
}
