{
  description = "a rust implementation of the 'crulz' macro language interpreter";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-20.09";
    flake-utils.url = "github:numtide/flake-utils";
    # needed for default.nix, shell.nix
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, flake-utils, flake-compat }:
    let
      progname = "crulz";
      overlay = final: prev: {
        ${progname} = (prev.pkgs.callPackage ./Cargo.nix {}).rootCrate.build;
      };
    in {
      overlay = overlay;
    } // flake-utils.lib.eachDefaultSystem
      (system:
        rec {
          defaultPackage = (import nixpkgs {
            inherit system;
            overlays = [ overlay ];
          }).${progname};
          defaultApp = flake-utils.lib.mkApp { drv = defaultPackage; };
          packages.${progname} = defaultPackage;
          apps.${progname} = defaultApp;
        }
      );
}
