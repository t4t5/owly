# services.owly: owlyd, Owly's radio service, and the owly CLI.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.owly;
  # The interfaces a session creates (packaging/90-owly-unmanaged.conf).
  ifaces = [
    "awdl0"
    "owlymon0"
    "owlyibss0"
    "owlyap0"
    "owlygo0"
  ];
  toml = pkgs.formats.toml { };
in
{
  imports = [ ./omdrop-owl.nix ];

  options.services.owly = {
    enable = lib.mkEnableOption "Owly, AirDrop's Wi-Fi radio: owlyd and the owly CLI";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The owly package to use.";
    };

    settings = lib.mkOption {
      inherit (toml) type;
      default = { };
      example = {
        station = "wlp1s0";
        allow_untested = true;
        channels = [ 149 ];
      };
      description = "/etc/owly/radio.toml: how the radio is set up on this machine. See crates/owly-radio/src/config.rs for the keys.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Open TCP 8771, where `owly receive` listens, on awdl0.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    # owlyd's unit, and its D-Bus name, policy and activation file. D-Bus
    # starts it on the first call.
    systemd.packages = [ cfg.package ];
    services.dbus.packages = [ cfg.package ];
    security.polkit.enable = true;
    # owly send wakes Apple receivers with a BLE advert through BlueZ;
    # without it, sending reaches only phones already listening.
    hardware.bluetooth.enable = lib.mkDefault true;

    # What owlyd runs: nmcli to release and reconnect the station, from the
    # system's NetworkManager (an nmcli newer than the daemon can't release
    # it, "No such method SetManaged"); ip and ping for shared mode's check
    # that Wi-Fi passes traffic; mount for debugfs.
    systemd.services.owlyd.path = [
      config.networking.networkmanager.package
      pkgs.iproute2
      pkgs.iputils
      pkgs.util-linux
    ];

    environment.etc."owly/radio.toml" = lib.mkIf (cfg.settings != { }) {
      source = toml.generate "radio.toml" cfg.settings;
    };

    networking.networkmanager.unmanaged = map (i: "interface-name:${i}") ifaces;
    networking.firewall.interfaces.awdl0.allowedTCPPorts = lib.mkIf cfg.openFirewall [ 8771 ];

    # packaging/10-owly-awdl0.link: udev must not give awdl0 a MAC address
    # of its own (AWDL-2).
    systemd.network.links."10-owly-awdl0" = {
      matchConfig.OriginalName = "awdl0";
      linkConfig.MACAddressPolicy = "none";
    };

    # NixOS restarts wpa_supplicant whenever a Wi-Fi interface comes or goes,
    # which drops the connection each time a session's monitor interface
    # does.
    services.udev.packages = [
      (pkgs.writeTextDir "lib/udev/rules.d/00-owly.rules" ''
        SUBSYSTEM=="net", KERNEL=="${lib.concatStringsSep "|" ifaces}", RUN:="${pkgs.coreutils}/bin/true"
      '')
    ];
  };
}
