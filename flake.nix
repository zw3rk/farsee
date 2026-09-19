# SPDX-License-Identifier: Apache-2.0
#
# Nix flake for the farsee RFB/VNC/RDP terminal client.
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
  description = "farsee: C11 RFB/VNC/RDP Kitty client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs =
    { self, nixpkgs }:
    let
      # Host systems declared in plan.md §7.1.
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

      # FreeRDP is Apache-2.0, but the stock desktop-client build links a
      # large media/device closure that includes licenses outside farsee's
      # release allowlist. Keep the RDP client libraries and cliprdr while
      # disabling server, GUI, media, audio, camera, print, smart-card and
      # device-redirection features. The runtime-closure gate verifies the
      # result from the final farsee binary; these flags are not trusted as
      # evidence on their own.
      mkFarseeFreeRDP =
        pkgs:
        pkgs.freerdp.overrideAttrs (old: {
          pname = "farsee-freerdp-minimal";
          cmakeFlags =
            (old.cmakeFlags or [ ])
            ++ [
              "-DBUILD_TESTING=OFF"
              "-DWITH_CLIENT=ON"
              "-DWITH_CLIENT_CHANNELS=ON"
              "-DWITH_CHANNELS=ON"
              "-DCHANNEL_CLIPRDR=ON"
              "-DWITH_SERVER=OFF"
              "-DWITH_SERVER_CHANNELS=OFF"
              "-DWITH_SERVER_INTERFACE=OFF"
              "-DWITH_PLATFORM_SERVER=OFF"
              "-DWITH_SHADOW=OFF"
              "-DWITH_PROXY=OFF"
              "-DWITH_PROXY_APP=OFF"
              "-DWITH_SAMPLE=OFF"
              "-DWITH_CLIENT_INTERFACE=OFF"
              "-DWITH_CLIENT_MAC=OFF"
              "-DWITH_CLIENT_SDL=OFF"
              "-DWITH_CLIENT_SDL2=OFF"
              "-DWITH_CLIENT_SDL3=OFF"
              "-DWITH_X11=OFF"
              "-DWITH_CAIRO=OFF"
              "-DWITH_RDTK=OFF"
              "-DWITH_FFMPEG=OFF"
              "-DWITH_DSP_FFMPEG=OFF"
              "-DWITH_VIDEO_FFMPEG=OFF"
              "-DWITH_SWSCALE=OFF"
              "-DWITH_GFX_H264=OFF"
              "-DWITH_OPENH264=OFF"
              "-DWITH_VAAPI=OFF"
              "-DWITH_OPENCL=OFF"
              "-DWITH_FAAD2=OFF"
              "-DWITH_OPUS=OFF"
              "-DWITH_SOXR=OFF"
              "-DWITH_JPEG=OFF"
              "-DWITH_LODEPNG=OFF"
              "-DWITH_PULSE=OFF"
              "-DWITH_MACAUDIO=OFF"
              "-DWITH_CUPS=OFF"
              "-DWITH_PCSC=OFF"
              "-DWITH_SMARTCARD_PCSC=OFF"
              "-DWITH_PKCS11=OFF"
              "-DWITH_FUSE=OFF"
              "-DWITH_KRB5=OFF"
              "-DWITH_AAD=OFF"
              "-DWITH_MANPAGES=OFF"
              "-DWITH_WINPR_TOOLS=OFF"
              "-DWITH_WINPR_TOOLS_CLI=OFF"
              "-DCHANNEL_AUDIN=OFF"
              "-DCHANNEL_RDPSND=OFF"
              "-DCHANNEL_RDPDR=OFF"
              "-DCHANNEL_URBDRC=OFF"
              "-DCHANNEL_TSMF=OFF"
              "-DCHANNEL_VIDEO=OFF"
            ]
            # Darwin stdenv exposes libintl to every link. FreeRDP does not
            # use its symbols, so discard that unused dynamic dependency.
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-dead_strip_dylibs"
            ];
        });

      # Library flag exports used by both the package build and the devShell
      # (zlib / OpenSSL / FreeRDP 3.x). Pure derivations cannot rely on
      # shellHook, so the package sets these in preConfigure.
      libFlagExports =
        pkgs: freerdp:
        ''
          export ZLIB_CFLAGS="-I${pkgs.zlib.dev}/include"
          export ZLIB_LIBS="-L${pkgs.zlib.out}/lib -lz"
          export OPENSSL_CFLAGS="-I${pkgs.openssl.dev}/include"
          export OPENSSL_LIBS="-L${pkgs.openssl.out}/lib -lssl -lcrypto"
          # FreeRDP 3.x for the RDP engine (optional, FARSEE_WITH_RDP).
          # freerdp3 + freerdp-client3 (LoadChannels / static addins / cliprdr)
          # + winpr3 (WinPR is FreeRDP's companion lib, separate .pc).
          export PKG_CONFIG_PATH="${freerdp.out}/lib/pkgconfig''${PKG_CONFIG_PATH:+:}$PKG_CONFIG_PATH"
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
            # Keep capture dumps and tool output out of every store import.
            && base != "captures"
            && base != "1"
            && base != "1.meta"
            && !pkgs.lib.hasSuffix ".plist" path
            && pkgs.lib.cleanSourceFilter path type;
        };

      # Shared devShell builder. macOS uses CommonCrypto for classic VNC DES
      # and OpenSSL for Apple authentication; Linux uses OpenSSL for both.
      # The devShell exports the Xcode SDK path for CommonCrypto headers.
      mkDevShell =
        { pkgs, system }:
        let
          isDarwin = pkgs.stdenv.isDarwin;
          freerdp = mkFarseeFreeRDP pkgs;
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
              pkgs.gnutar # deterministic archives on approved release hosts
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
              freerdp # minimized FreeRDP client closure
              pkgs.pkg-config # freerdp3 .pc discovery
              pkgs.syft # established SPDX/CycloneDX SBOM generator
              pkgs.cosign # established release-metadata signing tool
              pkgs.gitleaks # current-tree and reachable-history secret scanner
              # --- RDP interoperability lab infrastructure (gate R6) ---
              # QEMU + cloud-utils for the local interop lab (QEMU+HVF). These
              # are TEST-INFRASTRUCTURE ONLY: not linked into Farsee, not
              # exposed in any application header. Used to provision
              # independent RDP endpoints (xrdp, Windows eval) for gate R6.
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
            ${libFlagExports pkgs freerdp}
            export FARSEE_SOURCE_REV="${self.rev or self.dirtyRev or "unknown"}"
            export SOURCE_DATE_EPOCH="${toString (self.lastModified or 1)}"
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
          freerdp = mkFarseeFreeRDP pkgs;
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
            freerdp
          ];

          enableParallelBuilding = true;

          preConfigure = ''
            export FARSEE_SOURCE_REV="${self.rev or self.dirtyRev or "unknown"}"
            export SOURCE_DATE_EPOCH="${toString (self.lastModified or 1)}"
            ${libFlagExports pkgs freerdp}
          '';

          # CLI only: full `make release` also builds farsee_tests (registry).
          buildPhase = ''
            runHook preBuild
            make release-cli VERSION="$version" CC=clang -j''${NIX_BUILD_CORES}
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin $out/share/doc/farsee
            install -m755 build/release/bin/farsee $out/bin/farsee
            install -m644 LICENSE NOTICE THIRD_PARTY_NOTICES.md \
              release/dependencies.json $out/share/doc/farsee/
            python3 tools/gen_release_metadata.py \
              $out/share/doc/farsee/release-metadata.json \
              --version "$version" --platform "${system}" \
              --revision "${self.rev or self.dirtyRev or "unknown"}" \
              --epoch "${toString (self.lastModified or 1)}"
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "C11 RFB/VNC/RDP Kitty client";
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
