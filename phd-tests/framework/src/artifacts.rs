// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Management of artifacts: guest OS and guest firmware images that can be
//! attached to guests.
//!
//! The runner requires a path to a TOML file defining a set of artifacts. This
//! file defines
//!
//! - an optional remote URI from which to download resources that are missing,
//! - a table of guest OS images, specifying the
//! [`crate::guest_os::GuestOsKind`] of each image and its metadata, and
//! - a table of guest firmware images (bootroms), specifying metadata for each
//! one.
//!
//! Artifact metadata includes
//!
//! - the path to the artifact relative to the local root directory,
//! - an optional SHA256 digest against which to compare the local artifact, and
//! - an optional path to the artifact relative to the remote URI from which the
//! artifact can be reacquired if it is missing or corrupted.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use ring::digest::{Digest, SHA256};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, info_span, instrument};

use crate::guest_os::GuestOsKind;

/// Errors that can arise while loading or interacting with an artifact store.
#[derive(Debug, Error)]
pub enum ArtifactStoreError {
    /// Raised when the local artifact root specified in the artifact TOML
    /// doesn't appear to exist.
    #[error("The local root directory {0} does not exist")]
    LocalRootNotFound(PathBuf),

    /// Raised when the local artifact root specified in the artifact TOML
    /// exists but doesn't appear to be a directory.
    #[error("The local root {0} is inaccessible or not a directory")]
    LocalRootNotDirectory(PathBuf),

    /// Raised by [`ArtifactStore::check_local_copies`] when an artifact is not
    /// usable (e.g. because it is missing or has an invalid digest) and cannot
    /// be fixed (because no remote path to it is present).
    #[error(
        "One or more artifacts had invalid contents; check logs for details"
    )]
    ArtifactContentsInvalid(),
}

/// A single artifact.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactMetadata {
    /// The path to the artifact relative to the root directory specified in
    /// this artifact's store.
    relative_local_path: PathBuf,

    /// An optional SHA256 digest for this artifact. If present, the artifact
    /// store will use this digest to determine whether the artifact can be used
    /// or should be replaced, possibly with an artifact in remote storage.
    expected_digest: Option<String>,

    /// An optional path to this artifact relative to the file server root
    /// stored in the artifact store. If present, the store will use this to
    /// replace the artifact at startup if it appears to be corrupted.
    remote_uri: Option<String>,
}

impl ArtifactMetadata {
    /// Determine whether a local artifact is present and usable under the terms
    /// specified in its metadata.
    fn check_local_artifact(
        &self,
        local_root: &Path,
        remote_uri: Option<&str>,
    ) -> Result<()> {
        let mut local_path = PathBuf::new();
        local_path.push(local_root);
        local_path.push(&self.relative_local_path);

        // There are four possibilities:
        //
        // 1. The artifact doesn't exist at the expected path.
        // 2. The artifact exists, but has no digest recorded in the store.
        // 3. The artifact exists and has a digest recorded in the store,
        //    but the digest on disk doesn't match it.
        // 4. The artifact exists and has digest that matches what's in the
        //    store.
        //
        // In cases 1 and 3, try to redownload the artifact. In cases 2 and
        // 4, accept the artifact as-is and continue.
        let exists = local_path.exists();
        if exists {
            match &self.expected_digest {
                None => {
                    info!("Artifact exists but has no digest in its metadata");
                    return Ok(());
                }
                Some(digest) => match hash_equals(&local_path, digest) {
                    Ok(()) => {
                        info!("Artifact digest OK");
                        return Ok(());
                    }
                    Err(_) => {
                        info!("Artifact digest mismatched, will replace it");
                    }
                },
            }
        } else {
            info!("Artifact does not exist, will download it");
        }

        // The artifact is not usable as-is. See if it can be reacquired from
        // the remote source.
        let remote_uri = remote_uri
            .ok_or_else(|| anyhow!("Can't download artifact: no remote URI"))?;
        if exists {
            info!(?local_path, "Removing mismatched artifact before replacing");
            std::fs::remove_file(&local_path)?;
        }

        let download_timeout = Duration::from_secs(600);
        info!(
            ?local_path,
            ?remote_uri,
            "Downloading artifact with timeout {:?}",
            download_timeout,
        );

        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(download_timeout)
            .build()?;
        let request = client.get(remote_uri).build()?;
        let response = client.execute(request)?;
        let mut new_file = std::fs::File::create(&local_path)?;
        new_file.write_all(&response.bytes()?)?;
        if let Some(digest) = &self.expected_digest {
            hash_equals(&local_path, digest)?;
        }

        // Make the artifact read-only to try to ensure tests can't change it.
        // Disks copied from this artifact will be edited to be writable.
        let mut permissions = new_file.metadata()?.permissions();
        permissions.set_readonly(true);
        new_file.set_permissions(permissions)?;

        Ok(())
    }
}

/// A wrapper for guest OS artifacts that includes their OS kind.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestOsArtifact {
    guest_os_kind: GuestOsKind,
    metadata: ArtifactMetadata,
}

/// A collection of artifacts that can be loaded by test VMs.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStoreConfig {
    /// A map from names to guest OS artifacts.
    guest_images: BTreeMap<String, GuestOsArtifact>,

    /// A map from names to bootrom artifact metadata.
    bootroms: BTreeMap<String, ArtifactMetadata>,
}

impl ArtifactStoreConfig {
    fn from_toml(raw_toml: &str) -> Result<Self> {
        let config = toml::de::from_str(raw_toml)?;
        info!(?config, "Parsed artifact store configuration");
        Ok(config)
    }
}

#[derive(Debug)]
pub struct ArtifactStore {
    /// The local directory into which to save artifacts.
    local_root: PathBuf,
    config: ArtifactStoreConfig,
}

impl ArtifactStore {
    /// Opens the supplied file, reads its contents, and uses
    /// [`ArtifactStore::from_toml`] to try to interpret those contents as TOML
    /// describing an artifact store.
    pub fn from_file(
        config_path: impl AsRef<Path>,
        local_root: PathBuf,
    ) -> Result<Self> {
        info!(path = ?config_path.as_ref(),
              "Reading artifact store configuration from file");
        let contents = std::fs::read_to_string(config_path.as_ref())?;
        Self::from_toml(&contents, local_root)
    }

    /// Interprets the supplied string as TOML and attempts to deserialize it as
    /// an artifact store.
    pub fn from_toml(raw_toml: &str, local_root: PathBuf) -> Result<Self> {
        info!(?local_root, "Initializing artifact store");
        let config = ArtifactStoreConfig::from_toml(raw_toml)?;
        let store = Self { local_root, config };
        store.verify()?;
        Ok(store)
    }

    /// Retrieves this store's local root directory.
    pub fn get_local_root(&self) -> &Path {
        &self.local_root
    }

    /// Given a guest OS artifact name, attempts to retrieve the corresponding
    /// artifact and return a path to its contents and its guest OS kind.
    pub fn get_guest_artifact_info_by_name(
        &self,
        artifact: &str,
    ) -> Option<(PathBuf, GuestOsKind)> {
        self.config.guest_images.get(artifact).map(|a| {
            (
                self.construct_full_path(&a.metadata.relative_local_path),
                a.guest_os_kind,
            )
        })
    }

    /// Given an artifact name, attempts to retrieve the guest firmware artifact
    /// with that name and returns the local path to that artifact.
    pub fn get_bootrom_by_name(&self, artifact: &str) -> Option<PathBuf> {
        self.config
            .bootroms
            .get(artifact)
            .map(|a| self.construct_full_path(&a.relative_local_path))
    }

    fn construct_full_path(&self, relative_path: &Path) -> PathBuf {
        let mut full = PathBuf::new();
        full.push(&self.local_root);
        full.push(relative_path);
        full
    }

    fn verify(&self) -> Result<()> {
        if !self.local_root.exists() {
            return Err(ArtifactStoreError::LocalRootNotFound(
                self.local_root.clone(),
            )
            .into());
        }
        if !self.local_root.is_dir() {
            return Err(ArtifactStoreError::LocalRootNotDirectory(
                self.local_root.clone(),
            )
            .into());
        }

        Ok(())
    }

    /// Verifies the existence and integrity of the local on-disk artifacts
    /// described by the store.
    ///
    /// Note: This routine may mutate artifacts on disk. This struct makes no
    /// attempt to synchronize these accesses between multiple threads. The
    /// caller is responsible for ensuring that it only checks local copies when
    /// no artifacts are otherwise in use.
    ///
    /// # Return value
    ///
    /// - `Ok` if all the artifacts exist and all the artifacts with digests in
    ///   store have matching digests on disk.
    /// - `Err(ArtifactStoreError::ArtifactContentsInvalid)` if one or more
    ///   artifacts could not be obtained or verified. The process logs contain
    ///   more information about the specific artifacts that failed and the
    ///   errors that caused those failures. Note that this routine checks all
    ///   artifacts in the store even if one fails.
    #[instrument(skip_all)]
    pub fn check_local_copies(&self) -> Result<()> {
        let mut all_ok = true;

        let iter = self
            .config
            .guest_images
            .iter()
            .map(|(k, v)| (k, &v.metadata))
            .chain(self.config.bootroms.iter());

        for (name, metadata) in iter {
            info!(?name, ?metadata, "Checking artifact");
            let span = info_span!("Artifact", ?name);
            let _guard = span.enter();
            if let Err(e) = metadata.check_local_artifact(
                &self.local_root,
                metadata.remote_uri.as_deref(),
            ) {
                error!(?e, "Metadata check failed");
                all_ok = false;
            }
        }

        all_ok
            .then_some(())
            .ok_or_else(|| ArtifactStoreError::ArtifactContentsInvalid().into())
    }
}

fn sha256_digest(file: &mut File) -> Result<Digest> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut context = ring::digest::Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}

fn hash_equals(path: impl AsRef<Path>, expected_digest: &str) -> Result<()> {
    let mut file = File::open(path.as_ref())?;
    let digest = hex::encode(sha256_digest(&mut file)?.as_ref());
    if digest != expected_digest {
        bail!(
            "Digest of {:#?} was {}, expected {}",
            path.as_ref(),
            digest,
            expected_digest
        );
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn store_to_from_toml() {
        let guest_artifact = GuestOsArtifact {
            guest_os_kind: GuestOsKind::Alpine,
            metadata: ArtifactMetadata {
                relative_local_path: "alpine.raw".into(),
                expected_digest: Some("abcd1234".to_string()),
                remote_uri: Some("https://127.0.0.1/alpine.raw".to_string()),
            },
        };

        let bootrom_artifact = ArtifactMetadata {
            relative_local_path: "OVMF_CODE.fd".into(),
            expected_digest: None,
            remote_uri: Some("https://127.0.0.1/OVMF_CODE.fd".to_string()),
        };

        let config = ArtifactStoreConfig {
            guest_images: BTreeMap::from([(
                "alpine".to_string(),
                guest_artifact,
            )]),
            bootroms: BTreeMap::from([(
                "bootrom".to_string(),
                bootrom_artifact,
            )]),
        };

        let out = toml::ser::to_string(&config).unwrap();
        println!("TOML serialization output: {}", out);
        let _: ArtifactStoreConfig = toml::de::from_str(&out).unwrap();
    }

    #[test]
    fn verify_raw_toml() {
        let raw = r#"
            [guest_images.alpine]
            guest_os_kind = "alpine"
            metadata.relative_local_path = "alpine.raw"
            metadata.expected_digest = "abcd1234"
            metadata.remote_uri = "https://127.0.0.1/alpine.raw"

            [bootroms.bootrom]
            relative_local_path = "OVMF_CODE.fd"
            remote_uri = "https://127.0.0.1/OVMF_CODE.fd"
        "#;

        let store = ArtifactStoreConfig::from_toml(raw).unwrap();
        println!("Generated store: {:#?}", store);

        let guest_image = store.guest_images.get("alpine").unwrap();
        assert!(matches!(guest_image.guest_os_kind, GuestOsKind::Alpine));
        assert_eq!(
            guest_image.metadata.relative_local_path.to_string_lossy(),
            "alpine.raw"
        );
        assert_eq!(
            guest_image.metadata.expected_digest.as_ref().unwrap(),
            "abcd1234"
        );
        assert_eq!(
            guest_image.metadata.remote_uri.as_ref().unwrap(),
            "https://127.0.0.1/alpine.raw"
        );

        let bootrom = store.bootroms.get("bootrom").unwrap();
        assert_eq!(
            bootrom.relative_local_path.to_string_lossy(),
            "OVMF_CODE.fd"
        );
        assert!(bootrom.expected_digest.is_none());
        assert_eq!(
            bootrom.remote_uri.as_ref().unwrap(),
            "https://127.0.0.1/OVMF_CODE.fd"
        );
    }
}
