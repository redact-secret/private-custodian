//! The delivery sink for released projections: one file per projection, never
//! overwritten.
//!
//! `deliver` is the last step of a release. It must be idempotent, because a
//! crash between delivery and the pipeline recording it makes the next pass
//! deliver again. The file is named by the public projection id, created with
//! `create_new`, written, synced and renamed into place from a temporary name.
//! If a file already exists it must hold exactly the same bytes (a repeat of
//! the same release: success, nothing written); different bytes under the same
//! id are a conflict and are refused.
//!
//! What the directory holds is already public by construction
//! (`ReleasedEnvelope` is only producible by a completed release), but it is
//! still created owner-only: publication to a destination is a separate,
//! deployment-owned step.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use custodian_disclosure::ports::Sink;
use custodian_disclosure::{DisclosureReason, ReleasedEnvelope};

pub struct DirSink {
    dir: PathBuf,
}

impl DirSink {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The file a projection id is delivered to.
    pub fn path_of(&self, projection_id: &str) -> PathBuf {
        self.dir.join(format!("{projection_id}.json"))
    }

    /// Every delivered file, sorted, for tests and status.
    pub fn delivered(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Sink for DirSink {
    fn deliver(&self, released: &ReleasedEnvelope) -> Result<(), DisclosureReason> {
        let bytes = released.to_bytes()?;
        let id = released
            .envelope()
            .common_fields()
            .projection_id
            .as_str()
            .to_owned();
        let path = self.path_of(&id);
        match std::fs::read(&path) {
            Ok(existing) if existing == bytes => return Ok(()),
            Ok(_) => return Err(DisclosureReason::DeliveryFailed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DisclosureReason::DeliveryFailed),
        }
        let tmp = self.dir.join(format!(".{id}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        write().map_err(|_| {
            let _ = std::fs::remove_file(&tmp);
            DisclosureReason::DeliveryFailed
        })
    }
}
