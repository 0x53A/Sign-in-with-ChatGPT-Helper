{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  packages = with pkgs; [ cargo rustc rustfmt clippy pkg-config nodejs ripgrep ];
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (with pkgs; [ libGL libxkbcommon wayland libx11 libxcursor libxi libxrandr ]);
}
