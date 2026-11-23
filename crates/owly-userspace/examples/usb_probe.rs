//! Hardware discovery probe for clean-room userspace USB Wi-Fi dongles.
//!
//! Run with:
//! `cargo run --features usb --example usb_probe`
//! `cargo run --features usb --example usb_probe -- --fw-check <rom_patch.bin> <fw.bin>`

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_arch = "wasm32"
))]
mod supported {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use owly_userspace::air::usb::{DetectedDongle, SupportedDongle, discover_dongles};
    use owly_userspace::usb_radio::nusb_transport::UsbRadioHandle;
    use owly_userspace::usb_radio::{
        Mt7612uCodec, Mt7612uFirmware, Mt7612uRomPatch, UsbChipset, select_endpoints,
    };

    fn read_sysfs_bulk_endpoints(dongle: &DetectedDongle) -> Vec<(u8, usize)> {
        let sys_usb = Path::new("/sys/bus/usb/devices");
        let Ok(entries) = fs::read_dir(sys_usb) else {
            return Vec::new();
        };
        let want_bus = dongle.bus_id.trim_start_matches('0');
        for entry in entries.flatten() {
            let dev_dir = entry.path();
            let busnum = fs::read_to_string(dev_dir.join("busnum")).unwrap_or_default();
            let devnum = fs::read_to_string(dev_dir.join("devnum")).unwrap_or_default();
            if busnum.trim().trim_start_matches('0') != want_bus {
                continue;
            }
            if devnum.trim().parse::<u8>().ok() != Some(dongle.device_address) {
                continue;
            }
            let Ok(subs) = fs::read_dir(&dev_dir) else {
                continue;
            };
            for sub in subs.flatten() {
                let p = sub.path();
                if !p.is_dir()
                    || !p
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().contains(':'))
                {
                    continue;
                }
                let eps = read_interface_bulk_endpoints(&p);
                if !eps.is_empty() {
                    return eps;
                }
            }
        }
        Vec::new()
    }

    fn read_interface_bulk_endpoints(intf_dir: &Path) -> Vec<(u8, usize)> {
        let mut eps = Vec::new();
        let Ok(entries) = fs::read_dir(intf_dir) else {
            return eps;
        };
        for entry in entries.flatten() {
            let ep_dir = entry.path();
            let Some(name) = ep_dir.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.starts_with("ep_") {
                continue;
            }
            let typ = fs::read_to_string(ep_dir.join("type")).unwrap_or_default();
            if typ.trim() != "Bulk" {
                continue;
            }
            let addr_raw = fs::read_to_string(ep_dir.join("bEndpointAddress")).unwrap_or_default();
            let mps_raw = fs::read_to_string(ep_dir.join("wMaxPacketSize")).unwrap_or_default();
            let Ok(addr) = u8::from_str_radix(addr_raw.trim().trim_start_matches("0x"), 16) else {
                continue;
            };
            let Ok(mps) = usize::from_str_radix(mps_raw.trim().trim_start_matches("0x"), 16) else {
                continue;
            };
            eps.push((addr, mps));
        }
        eps.sort_by_key(|&(addr, _)| addr);
        eps
    }

    fn run_fw_check(patch_path: &str, fw_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let patch_bytes = fs::read(patch_path)?;
        let fw_bytes = fs::read(fw_path)?;
        let patch = Mt7612uRomPatch::parse(&patch_bytes)?;
        let fw = Mt7612uFirmware::parse(&fw_bytes)?;
        let patch_chunks = Mt7612uCodec::fw_upload_chunks(
            Mt7612uCodec::PATCH_LOAD_ADDR,
            &patch.payload,
            Mt7612uCodec::ROM_PATCH_MAX_CHUNK_LEN,
        );
        let ilm_chunks = Mt7612uCodec::fw_upload_chunks(
            Mt7612uCodec::FW_ILM_LOAD_ADDR,
            &fw.ilm,
            Mt7612uCodec::FW_MAX_CHUNK_LEN,
        );
        let dlm_chunks = Mt7612uCodec::fw_upload_chunks(
            Mt7612uCodec::FW_DLM_LOAD_ADDR,
            &fw.dlm,
            Mt7612uCodec::FW_MAX_CHUNK_LEN,
        );
        println!(
            "ROM_PATCH platform={:?} build_time={:?} hw_sw=0x{:08x} patch_ver=0x{:08x} csum=0x{:04x} payload={} chunks={}",
            patch.platform,
            patch.build_time,
            patch.hw_sw_ver,
            patch.patch_ver,
            patch.checksum,
            patch.payload.len(),
            patch_chunks.len()
        );
        println!(
            "FW_IMAGE build_time={:?} build_ver={} fw_ver={} ilm={} (chunks={}) dlm={} (chunks={})",
            fw.build_time,
            fw.build_ver,
            fw.fw_ver,
            fw.ilm_len,
            ilm_chunks.len(),
            fw.dlm_len,
            dlm_chunks.len()
        );
        Ok(())
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if let Some(pos) = args.iter().position(|a| a == "--fw-check") {
            let patch_path = args
                .get(pos + 1)
                .ok_or("usage: usb_probe --fw-check <rom_patch.bin> <fw.bin>")?;
            let fw_path = args
                .get(pos + 2)
                .ok_or("usage: usb_probe --fw-check <rom_patch.bin> <fw.bin>")?;
            run_fw_check(patch_path, fw_path)?;
        }

        let dongles = discover_dongles()?;
        if dongles.is_empty() {
            println!("NO_SUPPORTED_DONGLE_FOUND");
            return Ok(());
        }

        for dongle in &dongles {
            let chipset = match dongle.kind {
                SupportedDongle::Ar9271 => UsbChipset::Ar9271,
                SupportedDongle::Mt7612u => UsbChipset::Mt7612u,
            };
            println!(
                "DONGLE kind={} vid_pid={:04x}:{:04x} bus={} dev={} product={:?}",
                dongle.kind.name(),
                dongle.vendor_id,
                dongle.product_id,
                dongle.bus_id,
                dongle.device_address,
                dongle.product
            );

            let sysfs_eps = read_sysfs_bulk_endpoints(dongle);
            if !sysfs_eps.is_empty() {
                println!("  sysfs_bulk_eps={sysfs_eps:02x?}");
                if let Some(sel) = select_endpoints(chipset, &sysfs_eps) {
                    println!(
                        "  selected_eps tx=0x{:02x} rx=0x{:02x} cmd_out={:?} cmd_in={:?} in_mps={}",
                        sel.bulk_out_ep,
                        sel.bulk_in_ep,
                        sel.cmd_out_ep.map(|e| format!("0x{e:02x}")),
                        sel.cmd_in_ep.map(|e| format!("0x{e:02x}")),
                        sel.in_max_packet
                    );
                }
            }

            match UsbRadioHandle::open(dongle) {
                Ok(handle) => {
                    println!(
                        "  nusb_open=OK intf={} tx=0x{:02x} rx=0x{:02x} cmd_out={:?} cmd_in={:?} in_mps={}",
                        handle.interface_number,
                        handle.bulk_out_ep,
                        handle.bulk_in_ep,
                        handle.cmd_out_ep.map(|e| format!("0x{e:02x}")),
                        handle.cmd_in_ep.map(|e| format!("0x{e:02x}")),
                        handle.in_max_packet
                    );
                    if handle.kind == SupportedDongle::Mt7612u {
                        match handle
                            .read_reg_u32(Mt7612uCodec::REG_ASIC_VERSION, Duration::from_secs(1))
                        {
                            Ok(ver) => println!("  asic_version=0x{ver:08x}"),
                            Err(e) => println!("  asic_version=ERR ({e})"),
                        }
                    }
                }
                Err(err) => {
                    println!("  nusb_open=UNAVAILABLE ({err})");
                }
            }
        }

        Ok(())
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_arch = "wasm32"
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    supported::run()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_arch = "wasm32"
)))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("nusb device enumeration is unavailable on this target".into())
}
