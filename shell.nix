{ }:

let
  # Update packages with `nixpkgs-update` command
  pkgs =
    import
      (fetchTarball "https://github.com/NixOS/nixpkgs/archive/a595dde4d0d31606e19dcec73db02279db59d201.tar.gz")
      { };

  projectDir = toString ./.;

  pythonLibs = with pkgs; [
    zlib.out
    stdenv.cc.cc.lib
  ];
  python' =
    with pkgs;
    symlinkJoin {
      name = "python";
      paths = [ python314 ];
      buildInputs = [ makeWrapper ];
      postBuild = ''
        wrapProgram "$out/bin/python3.14" \
          --prefix ${if stdenv.isDarwin then "DYLD_LIBRARY_PATH" else "LD_LIBRARY_PATH"} : \
          "${lib.makeLibraryPath pythonLibs}"
      '';
    };

  packages' = with pkgs; [
    coreutils
    hatch
    jq
    python'
    ruff
    uv

    (writeShellScriptBin "run-tests" ''
      exec python -m pytest \
        --verbose \
        --no-header
    '')
    (writeShellScriptBin "nixpkgs-update" ''
      set -e
      hash=$(
        curl -sSL \
          https://prometheus.nixos.org/api/v1/query \
          -d 'query=channel_revision{channel="nixpkgs-unstable"}' \
        | jq -r ".data.result[0].metric.revision")
      sed -i "s|nixpkgs/archive/[0-9a-f]\\{40\\}|nixpkgs/archive/$hash|" shell.nix
      echo "Nixpkgs updated to $hash"
    '')
  ];

  shell' = with pkgs; ''
    export TZ=UTC
    export NIX_SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt
    export SSL_CERT_FILE=$NIX_SSL_CERT_FILE
    export PYTHONNOUSERSITE=1
    export PYTHONPATH="${projectDir}"

    current_python=$(readlink -e .venv/bin/python || echo "")
    current_python=''${current_python%/bin/*}
    [ "$current_python" != "${python'}" ] && rm -rf .venv/

    echo "Installing Python dependencies"
    export UV_PYTHON="${python'}/bin/python"
    uv sync --frozen

    echo "Activating environment"
    source .venv/bin/activate
  '';
in
pkgs.mkShell {
  buildInputs = packages';
  shellHook = shell';
}
