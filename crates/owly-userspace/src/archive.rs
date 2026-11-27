//! In-memory AirDrop `/Ask` offer + compressed `odc` CPIO builder (`Gzip` / `DVZip`).

use std::collections::BTreeSet;

use flate2::Compression;
use owly_airdrop::proto::archive::compress::{Compressor, Encoder};
use owly_airdrop::proto::archive::cpio::{
    Entry, MODE_DIR, MODE_FILE, ODC_MAX_SIZE, odc_header, odc_trailer,
};
use owly_airdrop::proto::archive::extract::RelPath;
use owly_airdrop::proto::messages::{AskFile, Offer};
use owly_airdrop::proto::sender::uti;

/// Builds an in-memory AirDrop [`Offer`] and compressed `odc` CPIO archive payload.
///
/// Each tuple is `(file_name, bytes)`. No temporary files or filesystem calls are performed.
pub fn build_in_memory_upload(
    files: &[(String, Vec<u8>)],
    compressor: Compressor,
) -> Result<(Offer, Vec<u8>), String> {
    if files.is_empty() {
        return Err("at least one file is required".into());
    }
    let mut items = Vec::with_capacity(files.len());
    let mut names = BTreeSet::new();
    let mut raw = odc_header(&Entry {
        name: ".".into(),
        mode: MODE_DIR | 0o755,
        size: 0,
        nlink: 1,
        ino: 1,
        uid: 501,
        gid: 20,
        mtime: 0,
    });

    for (idx, (name, data)) in files.iter().enumerate() {
        RelPath::file_name(name).map_err(|e| e.to_string())?;
        if !names.insert(name.as_str()) {
            return Err(format!("two items are called {name}"));
        }
        let size = u64::try_from(data.len()).map_err(|_| format!("{name:?} is too large"))?;
        if size > ODC_MAX_SIZE {
            return Err(format!("{name:?} exceeds the odc file-size limit"));
        }
        let ino = u32::try_from(idx + 2).unwrap_or(u32::MAX);
        raw.extend_from_slice(&odc_header(&Entry {
            name: name.clone(),
            mode: MODE_FILE | 0o644,
            size,
            nlink: 1,
            ino,
            uid: 501,
            gid: 20,
            mtime: 0,
        }));
        raw.extend_from_slice(data);
        items.push(AskFile {
            name: name.clone(),
            file_type: uti(name, false).into(),
            size: Some(size),
            bom_path: format!("./{name}"),
            is_directory: false,
        });
    }
    raw.extend_from_slice(&odc_trailer());

    let mut enc = Encoder::new(compressor, Compression::fast());
    let mut compressed = enc.write(&raw);
    compressed.extend_from_slice(&enc.finish());
    Ok((Offer::Files(items), compressed))
}
