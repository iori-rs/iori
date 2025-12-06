{
  description = "Iori";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      naersk,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        naersk-lib = pkgs.callPackage naersk { };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
          ];
        };
      in
      {
        packages.default = naersk-lib.buildPackage {
          src = ./.;
          nativeBuildInputs = with pkgs; [
            pkg-config
            rustPlatform.bindgenHook
          ];
          buildInputs = with pkgs; [
            protobuf
          ];
          cargoBuildOptions = opts: opts ++ [ "--workspace" ];
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            rust-analyzer
            pkg-config
            rustPlatform.bindgenHook # for clang
            nasm
            protobuf
            gcc # ffmpeg uses gcc to check host C11 support

            mkvtoolnix-cli
          ];
          env = {
            LC_ALL = "C";
          };
          shellHook = ''
            pushd crates/iori-ffmpeg
            ./build/build.rs

            export FFMPEG_INCLUDE_DIR="$PWD/tmp/ffmpeg_build/include"
            export FFMPEG_PKG_CONFIG_PATH="$PWD/tmp/ffmpeg_build/lib/pkgconfig"
            export PKG_CONFIG_PATH_FOR_TARGET="$PKG_CONFIG_PATH_FOR_TARGET:$FFMPEG_PKG_CONFIG_PATH"
            popd
          '';
        };
      }
    );
}
