//! Atomic file persistence helpers using `tempfile` + permission enforcement + rename.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use tempfile::NamedTempFile;

use crate::error::{BridgeError, Result};

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Atomically writes `bytes` to `path` via a sibling temporary file, sets Unix `mode`
/// (e.g. `0o600` for secrets/state, `0o644` for public assets), flushes/syncs, and renames.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = parent_dir(path);

    std::fs::create_dir_all(parent)
        .map_err(|e| BridgeError::io(format!("create_dir_all {}", parent.display()), e))?;

    let mut tmp = NamedTempFile::new_in(parent)
        .map_err(|e| BridgeError::io(format!("create temp file in {}", parent.display()), e))?;

    tmp.write_all(bytes)
        .map_err(|e| BridgeError::io(format!("write temp file for {}", path.display()), e))?;
    tmp.flush()
        .map_err(|e| BridgeError::io(format!("flush temp file for {}", path.display()), e))?;

    tmp.as_file()
        .sync_all()
        .map_err(|e| BridgeError::io(format!("sync temp file for {}", path.display()), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| {
                BridgeError::io(format!("chmod {:o} temp file for {}", mode, path.display()), e)
            })?;
    }
    #[cfg(not(unix))]
    let _ = mode;

    tmp.persist(path)
        .map_err(|e| BridgeError::io(format!("persist {}", path.display()), e.error))?;

    // Best-effort parent directory sync so the directory entry survives power loss.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Atomically serializes `val` as JSON and writes it to `path` with mode `0o600`.
pub fn atomic_write_json<T: Serialize + ?Sized>(path: &Path, val: &T, pretty: bool) -> Result<()> {
    let bytes = if pretty {
        serde_json::to_vec_pretty(val)
    } else {
        serde_json::to_vec(val)
    }
    .map_err(|e| BridgeError::json(format!("serialize {}", path.display()), e))?;

    atomic_write_bytes(path, &bytes, 0o600)
}

/// Atomically writes UTF-8 text to `path` with the given Unix `mode`.
pub fn atomic_write_text(path: &Path, text: &str, mode: u32) -> Result<()> {
    atomic_write_bytes(path, text.as_bytes(), mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_bytes_creates_dirs_sets_mode_and_replaces() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("nested").join("secret.bin");

        atomic_write_bytes(&target, b"first", 0o600).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        atomic_write_bytes(&target, b"second-payload", 0o644).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second-payload");
        let mode2 = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode2, 0o644);
    }

    #[test]
    fn atomic_write_json_sets_0600_and_supports_pretty_and_compact() {
        let dir = TempDir::new().unwrap();
        let compact_path = dir.path().join("compact.json");
        let pretty_path = dir.path().join("pretty.json");

        let payload = serde_json::json!({"ok": true, "count": 42});
        atomic_write_json(&compact_path, &payload, false).unwrap();
        atomic_write_json(&pretty_path, &payload, true).unwrap();

        let c_raw = std::fs::read_to_string(&compact_path).unwrap();
        let p_raw = std::fs::read_to_string(&pretty_path).unwrap();
        assert!(!c_raw.contains('\n'));
        assert!(p_raw.contains('\n'));
        assert_eq!(
            std::fs::metadata(&compact_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&pretty_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn parent_dir_handles_bare_filename_and_nested_paths() {
        assert_eq!(parent_dir(Path::new("bare.txt")), Path::new("."));
        assert_eq!(parent_dir(Path::new("/var/lib/a/b.json")), Path::new("/var/lib/a"));
        assert_eq!(parent_dir(Path::new("rel/b.json")), Path::new("rel"));
    }
}
