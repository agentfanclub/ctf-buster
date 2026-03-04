{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    inputs@{
      flake-parts,
      rust-overlay,
      crane,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { system, ... }:
        let
          overlays = [ rust-overlay.overlays.default ];
          pkgs = import inputs.nixpkgs {
            inherit system overlays;
            config.allowUnfree = true;
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          ctf-cli = craneLib.buildPackage {
            src = craneLib.cleanCargoSource ./.;
            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs; [
              openssl
              dbus
            ];
          };

          # Python 3.13 — angr 9.2.193 needs setuptools-rust (broken in nixpkgs), and
          # pycparser 3.00 breaks pyvex (removed CLexer.filename setter). Fix both:
          # pin angr stack to 9.2.154 and pycparser to 2.22 (last 2.x release).
          python313 = pkgs.python313.override {
            packageOverrides = _pyfinal: pyprev: {
              pycparser = pyprev.pycparser.overridePythonAttrs {
                version = "2.22";
                src = pkgs.fetchFromGitHub {
                  owner = "eliben";
                  repo = "pycparser";
                  tag = "release_v2.22";
                  hash = "sha256-RY0xQ4Mj8IfYAcypZQx4lDBmcgzYqtM4ARm9NSccBgA=";
                };
                doCheck = false;
              };
              cffi = pyprev.cffi.overridePythonAttrs {
                doCheck = false;
              };
              angr = pyprev.angr.overridePythonAttrs {
                version = "9.2.154";
                src = pkgs.fetchFromGitHub {
                  owner = "angr";
                  repo = "angr";
                  tag = "v9.2.154";
                  hash = "sha256-aOgZXHk6GTWZAEraZQahEXUYs8LWAWv1n9GfX+2XTPU=";
                };
                doCheck = false;
              };
              ailment = pyprev.ailment.overridePythonAttrs {
                version = "9.2.154";
                src = pkgs.fetchFromGitHub {
                  owner = "angr";
                  repo = "ailment";
                  tag = "v9.2.154";
                  hash = "sha256-JjS+jYWrbErkb6uM0DtB5h2ht6ZMmiYOQL/Emm6wC5U=";
                };
              };
              claripy = pyprev.claripy.overridePythonAttrs {
                version = "9.2.154";
                src = pkgs.fetchFromGitHub {
                  owner = "angr";
                  repo = "claripy";
                  tag = "v9.2.154";
                  hash = "sha256-90JX+VDWK/yKhuX6D8hbLxjIOS8vGKrN1PKR8iWjt2o=";
                };
              };
            };
          };

          pythonEnv = python313.withPackages (
            ps: with ps; [
              # Security / CTF
              angr
              beautifulsoup4
              capstone
              cryptography
              evtx
              fickling
              flask
              gmpy2
              impacket
              keystone-engine
              lxml
              numpy
              opencv4
              paramiko
              pefile
              pillow
              pip
              pycryptodome
              pwntools
              requests
              ropgadget
              ropper
              scapy
              sympy
              tqdm
              unicorn
              uvicorn
              z3-solver
              # MCP server framework
              fastmcp
              # Testing
              pytest
              pytest-cov
            ]
          );

          # Security CLI tools matching ~/.nixos-config/modules/profiles/security.nix
          securityTools = with pkgs; [
            adidnsdump
            aircrack-ng
            amass
            android-tools
            apktool
            aria2
            arjun
            arp-scan
            autopsy
            bandwhich
            bettercap
            binutils
            binwalk
            bloodhound
            bloodhound-py
            bulk_extractor
            bully
            burpsuite
            cadaver
            certipy
            checksec
            chisel
            coercer
            commix
            crowbar
            crunch
            cewl
            cutter
            dalfox
            davtest
            dex2jar
            dnsrecon
            dnsutils
            dnsx
            doggo
            elfutils
            enum4linux
            enum4linux-ng
            ettercap
            evil-winrm
            exiftool
            exploitdb
            eyewitness
            fcrackzip
            feroxbuster
            ffuf
            fierce
            file
            foremost
            fping
            freerdp
            frida-tools
            gau
            gdb
            ghidra
            gitleaks
            gobuster
            gowitness
            haiti
            hakrawler
            hash-identifier
            hashcat
            hashcat-utils
            hcxdumptool
            hcxtools
            httpie
            httpx
            iaito
            inetutils
            iperf3
            ipmitool
            jadx
            john
            joomscan
            jwt-cli
            katana
            kerbrute
            laudanum
            ldeep
            lftp
            libseccomp
            ligolo-ng
            lldb
            ltrace
            macchanger
            mariadb
            massdns
            masscan
            medusa
            metasploit
            mimikatz
            mitmproxy
            mtr
            nasm
            nbtscan
            net-snmp
            netcat-gnu
            netdiscover
            netexec
            nikto
            nmap
            nuclei
            one_gadget
            onesixtyone
            openvpn
            parsero
            patchelf
            pdfcrack
            pdfrip
            pixiewps
            powershell
            proxychains-ng
            radare2
            rdesktop
            reaverwps-t6x
            recon-ng
            redis
            remmina
            responder
            rizin
            rlwrap
            rustscan
            (sage.override { requireSageTests = false; })
            samba
            seclists
            sherlock
            sleuthkit
            smbmap
            smtp-user-enum
            social-engineer-toolkit
            socat
            sqlmap
            sshpass
            sshuttle
            starkiller
            steghide
            stegsolve
            step-cli
            strace
            subfinder
            tcpdump
            testdisk
            testssl
            thc-hydra
            theharvester
            tigervnc
            tor
            torsocks
            trippy
            trufflehog
            upx
            valgrind
            volatility3
            vt-cli
            wabt
            wafw00f
            waybackurls
            whatweb
            whois
            wifite2
            wireguard-tools
            wireshark-cli
            wpscan
            xh
            xxd
            yara
            zsteg

            # Container tooling
            docker-client
          ];
        in
        {
          packages.default = ctf-cli;

          devShells.default = pkgs.mkShell {
            nativeBuildInputs = [
              # Rust toolchain
              rustToolchain
              pkgs.rust-analyzer
              pkgs.pkg-config
              pkgs.openssl
              pkgs.dbus
              pkgs.cargo-tarpaulin

              # Python with security packages + fastmcp
              pythonEnv
            ]
            ++ securityTools;

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

            shellHook = ''
              echo "ctf-buster dev shell — Rust + security toolkit + Python MCP servers"
            '';
          };
        };
    };
}
