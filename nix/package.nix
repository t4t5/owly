{
  lib,
  stdenv,
  fetchFromGitHub,
  cmake,
  pkg-config,
  libev,
  libnl,
  libpcap,
  python3,
  glib,
  bash,
  coreutils,
  findutils,
  gawk,
  gnugrep,
  gnused,
  hostapd,
  iproute2,
  iputils,
  iw,
  networkmanager,
  procps,
  systemd,
  util-linux,
}:

let
  # ../pins is the one place the upstream commits are set.
  pin = name: lib.head (builtins.match ".*\n${name}=([0-9a-f]+)\n.*" (builtins.readFile ../pins));

  omdrop-awdl = fetchFromGitHub {
    owner = "brentkearney";
    repo = "omdrop-awdl";
    rev = pin "OMDROP_AWDL_COMMIT";
    hash = "sha256-O1wKiexntsp5L3g9XeOT8s3s9+vepM9G7PCenkimKNk=";
  };

  python = python3.withPackages (ps: [
    ps.dbus-python
    ps.ifaddr
    ps.libarchive-c
    ps.pillow
    ps.pygobject3
    ps.zeroconf
  ]);

  runtimePath = lib.makeBinPath [
    python
    bash
    coreutils
    findutils
    gawk
    gnugrep
    gnused
    hostapd
    iproute2
    iputils
    iw
    networkmanager
    procps
    systemd
    util-linux
  ];

  fromAwdl = [
    "send-to-peer"
    "airdrop-send.py"
    "awdl-af-parse.py"
    "awdl_identity.py"
    "awdl_debug.py"
    "ble-airdrop-adv.py"
    "awdl-airdrop-adv.py"
    "awdl-mdns-respond.py"
  ];
in
stdenv.mkDerivation {
  pname = "omdrop-owl";
  version = lib.head (builtins.match ".*\npkgver=([^\n]+)\n.*" (builtins.readFile ../PKGBUILD));

  src = fetchFromGitHub {
    owner = "jedbillyb";
    repo = "owl";
    rev = pin "OWL_COMMIT";
    fetchSubmodules = true;
    hash = "sha256-wke+tR6E4mfmzlGw1tgXiYOkSxeIRvaOmOYNWXIUVR8=";
  };

  patches = map (p: ../patches + "/${p}") (
    lib.sort lib.lessThan (lib.attrNames (builtins.readDir ../patches))
  );

  nativeBuildInputs = [
    cmake
    pkg-config
  ];
  buildInputs = [
    libev
    libnl
    libpcap
    python
  ];

  cmakeFlags = [ "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" ];

  buildPhase = ''
    runHook preBuild
    cmake --build . --target owl -j$NIX_BUILD_CORES
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    lib=$out/lib/omdrop
    install -Dm755 daemon/owl $lib/owl
    for f in ${lib.concatStringsSep " " fromAwdl}; do
      install -m755 ${omdrop-awdl}/userspace/$f $lib/$f
    done
    install -m755 ${../userspace/omdrop-discoverable} $lib/omdrop-discoverable
    install -m644 ${../userspace/owl-profiles} $lib/owl-profiles
    patchShebangs $lib
    # pkexec clears the environment, so the helper sets its own PATH.
    sed -i '1a export PATH=${runtimePath} GI_TYPELIB_PATH=${glib.out}/lib/girepository-1.0' $lib/omdrop-discoverable

    mkdir -p $out/bin
    ln -s $lib/omdrop-discoverable $out/bin/awdl-discoverable
    ln -s $lib/send-to-peer $out/bin/send-to-peer

    install -Dm644 ${../packaging/omdrop-owl.policy} \
      $out/share/polkit-1/actions/io.github.t4t5.omdrop-owl.policy
    substituteInPlace $out/share/polkit-1/actions/io.github.t4t5.omdrop-owl.policy \
      --replace-fail /usr/lib/omdrop/omdrop-discoverable $lib/omdrop-discoverable
    runHook postInstall
  '';

  meta = {
    description = "AirDrop radio backend for omdrop on Wi-Fi cards without Apple's Broadcom firmware";
    homepage = "https://github.com/t4t5/omdrop-owl";
    license = with lib.licenses; [
      gpl3Plus
      gpl2Only
      isc
    ];
    platforms = lib.platforms.linux;
    mainProgram = "awdl-discoverable";
  };
}
