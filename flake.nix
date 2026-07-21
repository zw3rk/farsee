# SPDX-License-Identifier: Apache-2.0
#
# Nix flake for the farsee clean-room RFB/VNC/RDP terminal client.
#
# This flake provisions the entire build/test environment used by the
# project's self-documenting Makefile (see ADR-0006). The Makefile is the
# primary driver; nix exists only to provide a hermetic, reproducible
# toolchain (compilers, zlib, openssl, freerdp, lcov, coreutils, python).
#
# `nix develop` drops you into a shell where `make help` lists every target
# and `make` builds the default configuration.
# `nix build` / `nix run .#` produce and run the release CLI binary.
{
  description = "farsee: clean-room C11 RFB/VNC/RDP Kitty client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs =
    { self, nixpkgs }:
    let
      # Systems we actually support per plan.md §7.1.
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            pkgs = nixpkgs.legacyPackages.${system};
            inherit system;
          }
        );

      # Library flag exports used by both the package build and the devShell
      # (zlib / OpenSSL / FreeRDP 3.x). Pure derivations cannot rely on
      # shellHook, so the package sets these in preConfigure.
      libFlagExports =
        pkgs:
        ''
          export ZLIB_CFLAGS="-I${pkgs.zlib.dev}/include"
          export ZLIB_LIBS="-L${pkgs.zlib.out}/lib -lz"
          export OPENSSL_CFLAGS="-I${pkgs.openssl.dev}/include"
          export OPENSSL_LIBS="-L${pkgs.openssl.out}/lib -lssl -lcrypto"
          # FreeRDP 3.x for the RDP engine (optional, FARSEE_WITH_RDP).
          # freerdp3 + freerdp-client3 (LoadChannels / static addins / cliprdr)
          # + winpr3 (WinPR is FreeRDP's companion lib, separate .pc).
          export FREERDP_CFLAGS="$(pkg-config --cflags freerdp3 freerdp-client3 winpr3)"
          export FREERDP_LIBS="$(pkg-config --libs freerdp3 freerdp-client3 winpr3)"
        '';

      # Source tree for the package: drop VCS noise and local build artifacts
      # so impure host build/ state cannot poison a pure evaluation.
      packageSrc =
        pkgs:
        pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            let
              base = baseNameOf path;
            in
            base != "build"
            && base != "result"
            && base != ".direnv"
            && pkgs.lib.cleanSourceFilter path type;
        };

      # Shared devShell builder. On macOS we keep CommonCrypto reachable via
      # the Xcode SDK (the devShell exports SDKROOT). On Linux we provide
      # OpenSSL 3.x as the VNC-Authentication provider.
      mkDevShell =
        { pkgs, system }:
        let
          isDarwin = pkgs.stdenv.isDarwin;
          # LLVM 20.1.8: the oldest upstream whose ASan runtime works on
          # macOS 26 (darwin 25.x). LLVM 19's libclang_rt.asan_osx_dynamic
          # deadlocks in AsanInitFromRtl on this OS version (documented in
          # ADR-0006). LLVM 18 failed its compiler-rt bootstrap entirely.
          llvm = pkgs.llvmPackages_20;
        in
        pkgs.mkShell {
          pname = "farsee-devshell";
          packages =
            [
              # --- Compilers (the full required matrix) ---
              llvm.clang # Clang 20.1.8
              llvm.clang-tools # clang-tidy / clang-format
              llvm.lld # linker (parity with Linux)
              llvm.libllvm # provides llvm-cov for coverage aggregation
              pkgs.gcc # GCC 14.3.0 (real GCC, not Apple's alias)
              # --- Build tools ---
              pkgs.gnumake
              pkgs.coreutils # gsha256sum, grealpath, etc.
              # --- Libraries (with headers) ---
              pkgs.zlib.dev # ZRLE
              pkgs.openssl.dev # Linux VNC-Authentication provider
              # --- Test / coverage / analysis ---
              pkgs.python3 # scripted integration server + fixtures
              pkgs.lcov # coverage aggregation
              pkgs.gdb # optional crash debugging
              # --- Utility ---
              pkgs.git
              pkgs.which
              pkgs.freerdp # FreeRDP 3.x for the RDP engine (ADR-RDP-001, FARSEE_WITH_RDP)
              pkgs.sdl3 # FreeRDP client dlopens SDL3 (ASan/CI headless)
              pkgs.pkg-config # freerdp3 .pc discovery
              # --- RDP interop lab infrastructure (R6, §15.19) ---
              # QEMU + cloud-utils for the local interop lab (QEMU+HVF). These
              # are TEST-INFRASTRUCTURE ONLY: not linked into Farsee, not
              # exposed in any application header. Used to provision
              # independent RDP endpoints (xrdp, Windows eval) for §15.19.
              pkgs.qemu # QEMU 10.x with HVF accel for local VMs
              pkgs.cloud-utils # cloud-localds for cloud-init seed ISOs
              pkgs.sshpass # SSH into lab VMs for interactive debugging
              pkgs.cdrtools # mkisofs for Autounattend ISOs
            ];
          # Make the SDK and library paths discoverable for both compilers.
          shellHook = ''
            ${
              pkgs.lib.optionalString isDarwin ''
                # Locate Apple's system toolchain with the nix PATH *cleared*
                # so xcrun does not resolve to nix's own clang. The macOS
                # sanitizer build must use Apple's matched ASan runtime
                # (nix LLVM 19/20 ASan deadlocks on macOS 26 — ADR-0006).
                # We export the absolute path as MACOS_ASAN_CC for the Makefile.
                MACOS_ASAN_CC="$(env -i PATH=/usr/bin:/bin HOME="$HOME" xcrun --find clang 2>/dev/null || true)"
                if [ -n "$MACOS_ASAN_CC" ] && [ -x "$MACOS_ASAN_CC" ]; then
                  export MACOS_ASAN_CC
                  export SDKROOT="$(env -i PATH=/usr/bin:/bin HOME="$HOME" xcrun --show-sdk-path 2>/dev/null || true)"
                fi
              ''
            }
            ${libFlagExports pkgs}
            # FreeRDP may dlopen libSDL3 without an rpath entry; expose it for
            # tests under ASan/CI (see "Failed loading SDL3 library" abort).
            export LD_LIBRARY_PATH="${pkgs.sdl3}/lib''${LD_LIBRARY_PATH:+:}$LD_LIBRARY_PATH"
            export DYLD_LIBRARY_PATH="${pkgs.sdl3}/lib''${DYLD_LIBRARY_PATH:+:}$DYLD_LIBRARY_PATH"
            export SDL_VIDEODRIVER="''${SDL_VIDEODRIVER:-dummy}"
            export SDL_AUDIODRIVER="''${SDL_AUDIODRIVER:-dummy}"
            # Prefer nix-provided GNU coreutils for deterministic scripts.
            export PATH="${pkgs.coreutils}/bin:$PATH"
            echo "farsee devShell ready. Run 'make help' to see targets."
          '';
        };

      mkPackage =
        { pkgs, system }:
        let
          llvm = pkgs.llvmPackages_20;
        in
        pkgs.stdenv.mkDerivation {
          pname = "farsee";
          version = "0.1.0-dev";
          src = packageSrc pkgs;

          nativeBuildInputs = [
            pkgs.gnumake
            pkgs.pkg-config
            llvm.clang
            # `make release` → `build` also builds farsee_tests, which needs
            # the generated test registry (tools/gen_test_registry.py).
            pkgs.python3
          ];
          # Product link set only — no qemu/sshpass/lab tools (devShell only).
          buildInputs = [
            pkgs.zlib
            pkgs.openssl
            pkgs.freerdp
            pkgs.sdl3 # runtime dlopen from FreeRDP client
          ];

          enableParallelBuilding = true;

          preConfigure = libFlagExports pkgs;

          # CLI only: full `make release` also builds farsee_tests (registry).
          buildPhase = ''
            runHook preBuild
            make release-cli CC=clang -j''${NIX_BUILD_CORES}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -m755 build/release/bin/farsee $out/bin/farsee
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "clean-room C11 RFB/VNC/RDP Kitty client";
            homepage = "https://github.com/zw3rk/farsee";
            license = licenses.asl20;
            mainProgram = "farsee";
            platforms = systems;
          };
        };
    in
    {
      devShells = forAllSystems (
        { pkgs, system }:
        {
          default = mkDevShell { inherit pkgs system; };
        }
      );

      packages = forAllSystems (
        { pkgs, system }:
        {
          default = mkPackage { inherit pkgs system; };
        }
      );

      apps = forAllSystems (
        { pkgs, system }:
        {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/farsee";
          };
        }
      );
    };
}
