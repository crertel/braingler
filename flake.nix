{
  description = "braingler — Wake-on-LAN dashboard for homelab hosts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
            go-tools
            golangci-lint
            iputils
            nixfmt-rfc-style
          ];

          shellHook = ''
            export GOPATH="$PWD/.go"
            export GOCACHE="$PWD/.go/cache"
            export PATH="$GOPATH/bin:$PATH"
            echo "braingler dev shell — go $(go version | awk '{print $3}')"
          '';
        };

        packages.default = pkgs.buildGoModule {
          pname = "braingler";
          version = "0.0.1";
          src = ./.;
          vendorHash = null;
          subPackages = [ "." ];
          meta = with pkgs.lib; {
            description = "Wake-on-LAN dashboard for homelab hosts";
            license = licenses.mit;
            mainProgram = "braingler";
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/braingler";
        };
      });
}
