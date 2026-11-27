//! The extraction sandbox: a fresh staging directory that an upload is
//! written into, moved into the destination only once it's complete (SEC-1),
//! without overwriting anything there (SEC-2).
//!
//! Paths come from the extraction rules already validated, and only this
//! code creates anything in staging, so no entry in it can be a symlink or
//! lead outside it.

use std::io;
use std::path::{Path, PathBuf};

use tokio::fs;
use tokio::io::{AsyncWriteExt, BufWriter};

use crate::proto::archive::extract::{RelPath, collision_name};

const WRITE_BUF_BYTES: usize = 256 << 10;

pub struct Staging {
    dir: tempfile::TempDir,
    dest: PathBuf,
    file: Option<BufWriter<fs::File>>,
    /// Top-level names, in the order they arrived.
    top: Vec<String>,
}

impl Staging {
    /// A staging directory inside `dest`, so moving out of it is a rename.
    pub async fn new(dest: &Path) -> io::Result<Self> {
        fs::create_dir_all(dest).await?;
        let dest = dest.to_path_buf();
        let dir = tokio::task::spawn_blocking({
            let dest = dest.clone();
            move || {
                tempfile::Builder::new()
                    .prefix(".owly-staging-")
                    .tempdir_in(dest)
            }
        })
        .await
        .map_err(io::Error::other)??;
        Ok(Staging {
            dir,
            dest,
            file: None,
            top: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    fn join(&mut self, path: &RelPath) -> PathBuf {
        let first = &path.components()[0];
        if !self.top.contains(first) {
            self.top.push(first.clone());
        }
        let mut out = self.dir.path().to_path_buf();
        out.extend(path.components());
        out
    }

    pub async fn create_dir(&mut self, path: &RelPath) -> io::Result<()> {
        let path = self.join(path);
        fs::create_dir_all(path).await
    }

    pub async fn create_file(&mut self, path: &RelPath) -> io::Result<()> {
        self.end_file().await?;
        let path = self.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o644);
        self.file = Some(BufWriter::with_capacity(
            WRITE_BUF_BYTES,
            options.open(path).await?,
        ));
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.write_all(data).await,
            None => Err(io::Error::other("no file open")),
        }
    }

    pub async fn end_file(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
        }
        Ok(())
    }

    /// Moves everything into the destination, renaming on collision, and
    /// returns where each top-level item ended up. Staging is removed.
    pub async fn finish(mut self) -> io::Result<Vec<PathBuf>> {
        self.end_file().await?;
        let staging = self.dir.path().to_path_buf();
        let dest = self.dest.clone();
        let top = std::mem::take(&mut self.top);
        tokio::task::spawn_blocking(move || {
            let mut moved = Vec::new();
            for name in top {
                moved.push(move_unique(&staging.join(&name), &dest, &name)?);
            }
            Ok(moved)
        })
        .await
        .map_err(io::Error::other)?
        // `self.dir` is dropped here, removing staging and anything left in it.
    }
}

/// Renames `from` to `dest/name`, or the first free `name (n)`, never
/// replacing what's there (SEC-2).
fn move_unique(from: &Path, dest: &Path, name: &str) -> io::Result<PathBuf> {
    for n in 0..10_000 {
        let candidate = if n == 0 {
            name.to_string()
        } else {
            collision_name(name, n)
        };
        let to = dest.join(&candidate);
        match rename_noreplace(from, &to) {
            Ok(()) => return Ok(to),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free name"))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};
    renameat2(AT_FDCWD, from, AT_FDCWD, to, RenameFlags::RENAME_NOREPLACE).map_err(io::Error::from)
}

/// Without an atomic no-replace rename, check first. The race is with the
/// destination's owner, not with the sender.
#[cfg(not(target_os = "linux"))]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    if std::fs::symlink_metadata(to).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    std::fs::rename(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> RelPath {
        RelPath::parse(p).unwrap()
    }

    // spec: SEC-1, SEC-2
    #[tokio::test]
    async fn moves_into_place_without_overwriting() {
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(dest.path().join("a.txt"), b"mine").unwrap();
        let mut s = Staging::new(dest.path()).await.unwrap();
        let staging = s.path().to_path_buf();
        assert!(staging.starts_with(dest.path()));
        s.create_file(&path("a.txt")).await.unwrap();
        s.write(b"theirs").await.unwrap();
        s.create_dir(&path("d")).await.unwrap();
        s.create_file(&path("d/e/f")).await.unwrap();
        s.write(b"deep").await.unwrap();
        let moved = s.finish().await.unwrap();
        assert_eq!(
            moved,
            [dest.path().join("a (1).txt"), dest.path().join("d")]
        );
        assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"mine");
        assert_eq!(
            std::fs::read(dest.path().join("a (1).txt")).unwrap(),
            b"theirs"
        );
        assert_eq!(std::fs::read(dest.path().join("d/e/f")).unwrap(), b"deep");
        assert!(!staging.exists());
    }

    #[tokio::test]
    async fn dropping_discards_everything() {
        let dest = tempfile::tempdir().unwrap();
        let mut s = Staging::new(dest.path()).await.unwrap();
        s.create_file(&path("x")).await.unwrap();
        s.write(b"partial").await.unwrap();
        drop(s);
        assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn never_replaces_a_file_in_staging() {
        let dest = tempfile::tempdir().unwrap();
        let mut s = Staging::new(dest.path()).await.unwrap();
        s.create_file(&path("x")).await.unwrap();
        assert_eq!(
            s.create_file(&path("x")).await.unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }
}
