use std::path::Path;
use std::process::Command;

fn git(manifest: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let branch = std::env::var("OWLY_BUILD_BRANCH")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| git(&manifest, &["branch", "--show-current"]))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "detached".into());
    let hash = std::env::var("OWLY_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| git(&manifest, &["rev-parse", "--short=12", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=OWLY_BUILD_ID={version} ({branch} {hash})");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../build-info.rs");
    println!("cargo:rerun-if-env-changed=OWLY_BUILD_BRANCH");
    println!("cargo:rerun-if-env-changed=OWLY_BUILD_COMMIT");
    if let Some(head) = git(&manifest, &["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(reference) = git(&manifest, &["symbolic-ref", "HEAD"])
        && let Some(path) = git(&manifest, &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}
