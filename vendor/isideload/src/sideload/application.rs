// This file was made using https://github.com/Dadoum/Sideloader as a reference.
// I'm planning on redoing this later to better handle entitlements, extensions, etc, but it will do for now

use crate::SideloadError;
use crate::dev::app_ids::{AppId, AppIdsApi};
use crate::dev::developer_session::DeveloperSession;
use crate::dev::device_type::DeveloperDeviceType;
use std::collections::HashSet;
use crate::dev::teams::DeveloperTeam;
use crate::sideload::builder::ExtensionsBehavior;
use crate::sideload::bundle::Bundle;
use crate::sideload::cert_identity::CertificateIdentity;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit},
};
use isideload_vfs::fs::File;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::*;
use sha1::Digest;
use sha2::Sha256;
use std::io::Write;
use std::path::PathBuf;
use tracing::{info, warn};
use zip::ZipArchive;

static ALT_PAIRING_FILE: &str = "ALTPairingFile.dat";

pub struct Application {
    pub bundle: Bundle,
    //pub temp_path: PathBuf,
}

impl Application {
    pub fn new(path: PathBuf) -> Result<Self, Report> {
        if !isideload_vfs::fs::metadata(&path).is_ok() {
            bail!(SideloadError::InvalidBundle(
                "Application path does not exist".to_string(),
            ));
        }

        let mut bundle_path = path.clone();
        //let mut temp_path = PathBuf::new();

        if isideload_vfs::fs::metadata(&bundle_path)?.is_file() {
            let temp_dir = isideload_vfs::fs::temp_dir();
            let temp_path = temp_dir.join(
                path.file_name()
                    .ok_or_report()?
                    .to_string_lossy()
                    .to_string()
                    + "_extracted",
            );
            if isideload_vfs::fs::metadata(&temp_path).is_ok() {
                isideload_vfs::fs::remove_dir_all(&temp_path)
                    .context("Failed to remove existing temporary directory")?;
            }
            isideload_vfs::fs::create_dir_all(&temp_path)
                .context("Failed to create temporary directory")?;

            let file = File::open(&path).context("Failed to open application archive")?;
            let mut archive =
                ZipArchive::new(file).context("Failed to open application archive")?;

            archive
                .extract(&temp_path)
                .context("Failed to extract application archive")?;

            let payload_folder = temp_path.join("Payload");
            if isideload_vfs::fs::metadata(&payload_folder).is_ok() && payload_folder.is_dir() {
                let app_dirs: Vec<_> = isideload_vfs::fs::read_dir(&payload_folder)
                    .context("Failed to read Payload directory")?
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
                    .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "app"))
                    .collect();
                if app_dirs.len() == 1 {
                    bundle_path = app_dirs[0].path();
                } else if app_dirs.is_empty() {
                    bail!(SideloadError::InvalidBundle(
                        "No .app directory found in Payload".to_string(),
                    ));
                } else {
                    bail!(SideloadError::InvalidBundle(
                        "Multiple .app directories found in Payload".to_string(),
                    ));
                }
            } else {
                // gather the directory contents as a string for debugging
                let mut contents = String::new();
                if isideload_vfs::fs::metadata(&temp_path).is_ok() && temp_path.is_dir() {
                    let entries = isideload_vfs::fs::read_dir(&temp_path)
                        .context("Failed to read temporary directory for error reporting")?;
                    for entry in entries {
                        if let Ok(entry) = entry {
                            contents
                                .push_str(&format!("{}\n", entry.file_name().to_string_lossy()));
                        }
                    }
                }
                bail!(SideloadError::InvalidBundle(format!(
                    "No Payload directory found in the application archive, instead: {}",
                    contents
                ),));
            }
        }
        let bundle = Bundle::new(bundle_path)?;

        Ok(Application {
            bundle, /*temp_path*/
        })
    }

    pub fn get_special_app(&self) -> Option<SpecialApp> {
        let bundle_id = self.bundle.bundle_identifier().unwrap_or("");
        let special_app = match bundle_id {
            "com.rileytestut.AltStore" => Some(SpecialApp::AltStore),
            "com.SideStore.SideStore" => Some(SpecialApp::SideStore),
            "app.stik.store" => Some(SpecialApp::StikStore),
            _ => None,
        };
        if special_app.is_some() {
            return special_app;
        }

        if self
            .bundle
            .frameworks()
            .iter()
            .any(|f| f.bundle_identifier().unwrap_or("") == "com.SideStore.SideStore")
        {
            return Some(SpecialApp::SideStoreLc);
        }

        if bundle_id == "com.kdt.livecontainer" {
            return Some(SpecialApp::LiveContainer);
        }

        None
    }

    pub fn main_bundle_id(&self) -> Result<String, Report> {
        let str = self
            .bundle
            .bundle_identifier()
            .ok_or_report()
            .context("Failed to get main bundle identifier")?
            .to_string();

        Ok(str)
    }

    pub fn main_app_name(&self) -> Result<String, Report> {
        let str = self
            .bundle
            .bundle_name()
            .ok_or_report()
            .context("Failed to get main app name")?
            .to_string();

        Ok(str)
    }

    pub fn update_bundle_id(
        &mut self,
        main_app_bundle_id: &str,
        main_app_id_str: &str,
    ) -> Result<(), Report> {
        self.bundle.validate_watch_links(main_app_bundle_id, &self.watch_bundle_ids())?;
        self.bundle.rewrite_embedded_bundle_ids(main_app_bundle_id, main_app_id_str)?;
        self.bundle.set_bundle_identifier(main_app_id_str);
        Ok(())
    }

    /// IDs of Watch executables and their nested extensions, never frameworks/dylibs.
    pub fn watch_bundle_ids(&self) -> HashSet<String> {
        fn collect(bundle: &Bundle, watch: bool, ids: &mut HashSet<String>) {
            if watch {
                if let Some(id) = bundle.bundle_identifier() { ids.insert(id.to_string()); }
            }
            for ext in bundle.app_extensions() { collect(ext, watch, ids); }
            for child in bundle.watch_apps() { collect(child, true, ids); }
        }
        let mut ids = HashSet::new();
        collect(&self.bundle, false, &mut ids);
        ids
    }

    /// bool = reuse the phone profile. Watch bundles ALWAYS need explicit profiles,
    /// independently of the existing phone-extension callback's selected behavior.
    pub(crate) fn profile_targets(&self, mode: &ExtensionsBehavior) -> Vec<(&Bundle, bool)> {
        let watch = self.watch_bundle_ids();
        self.bundle.collect_app_id_bundles().into_iter().map(|bundle| {
            let reuse = matches!(mode, ExtensionsBehavior::ReuseMain)
                && bundle.bundle_dir != self.bundle.bundle_dir
                && !bundle.bundle_identifier().is_some_and(|id| watch.contains(id));
            (bundle, reuse)
        }).collect()
    }

    pub async fn register_app_ids(
        &self,
        mode: &ExtensionsBehavior,
        dev_session: &mut DeveloperSession,
        team: &DeveloperTeam,
    ) -> Result<Vec<AppId>, Report> {
        let watch = self.watch_bundle_ids();
        let targets = self.profile_targets(mode);
        let mut registered = Vec::new();
        for platform in [DeveloperDeviceType::Ios, DeveloperDeviceType::Watchos] {
            let is_watch = matches!(platform, DeveloperDeviceType::Watchos);
            let bundles: Vec<_> = targets.iter().filter(|(bundle, reuse)| {
                !reuse && bundle.bundle_identifier().is_some_and(|id| watch.contains(id) == is_watch)
            }).map(|(bundle, _)| *bundle).collect();
            if bundles.is_empty() { continue; }
            let response = dev_session.list_app_ids(team, Some(platform.clone())).await
                .context("Failed to list app IDs for the developer team")?;
            let missing = bundles.iter().filter(|bundle| !response.app_ids.iter().any(|id|
                Some(id.identifier.as_str()) == bundle.bundle_identifier())).count();
            if let Some(available) = response.available_quantity {
                if available < 0 {
                    warn!("Apple reports a negative number of available app IDs ({})", available);
                } else if missing as u64 > available as u64 {
                    bail!("Not enough available {:?} app IDs: {} required, {} available", platform, missing, available);
                }
            }
            for bundle in bundles {
                let id = bundle.bundle_identifier().ok_or_else(|| report!("Missing bundle identifier"))?;
                let app_id = match response.app_ids.iter().find(|app_id| app_id.identifier == id) {
                    Some(existing) => existing.clone(),
                    None => dev_session.add_app_id(team, bundle.bundle_name().unwrap_or("App"), id, Some(platform.clone())).await?,
                };
                registered.push(app_id);
            }
        }
        info!("Registered app IDs (including explicit watchOS IDs)");
        Ok(registered)
    }

    pub async fn apply_special_app_behavior(
        &mut self,
        special: &Option<SpecialApp>,
        group_identifier: &str,
        cert: &CertificateIdentity,
        pairing_file: Option<&[u8]>,
        device_udid: Option<&str>,
    ) -> Result<(), Report> {
        let Some(special) = special.as_ref() else {
            return Ok(());
        };

        if matches!(
            special,
            SpecialApp::SideStoreLc
                | SpecialApp::SideStore
                | SpecialApp::AltStore
                | SpecialApp::StikStore
        ) {
            if !matches!(special, SpecialApp::StikStore) {
                self.bundle.app_info.insert(
                    "ALTAppGroups".to_string(),
                    plist::Value::Array(vec![plist::Value::String(group_identifier.to_string())]),
                );
                let extensions = self.bundle.app_extensions_mut();
                for ext in extensions.iter_mut() {
                    ext.app_info.insert(
                        "ALTAppGroups".to_string(),
                        plist::Value::Array(vec![plist::Value::String(
                            group_identifier.to_string(),
                        )]),
                    );
                }
            }
            info!("Injecting certificate for {}", special);

            let target_bundle =
                match special {
                    SpecialApp::SideStoreLc => self.bundle.frameworks_mut().iter_mut().find(|fw| {
                        fw.bundle_identifier().unwrap_or("") == "com.SideStore.SideStore"
                    }),
                    _ => Some(&mut self.bundle),
                };

            if let Some(target_bundle) = target_bundle {
                let id_key = match special {
                    SpecialApp::StikStore => "MachineID",
                    _ => "ALTCertificateID",
                };
                let cert_file_name = match special {
                    SpecialApp::StikStore => "Certificate.p12",
                    _ => "ALTCertificate.p12",
                };
                target_bundle.app_info.insert(
                    id_key.to_string(),
                    plist::Value::String(cert.get_serial_number()),
                );

                let p12_bytes = cert
                    .as_p12(&cert.machine_id)
                    .await
                    .context("Failed to encode cert as p12")?;
                let alt_cert_path = target_bundle.bundle_dir.join(cert_file_name);

                let mut file = isideload_vfs::fs::File::create(&alt_cert_path)
                    .context(format!("Failed to create {}", cert_file_name))?;
                file.write_all(&p12_bytes)
                    .context(format!("Failed to write {}", cert_file_name))?;
            }
        }

        if matches!(special, SpecialApp::AltStore) {
            if let Some(pairing_file) = pairing_file {
                info!("Injecting pairing file for AltStore");

                let key_bytes = Sha256::digest(cert.machine_id.as_bytes());

                let cipher = Aes256Gcm::new(&key_bytes);

                let nonce = Nonce::generate();
                let ciphertext = cipher.encrypt(&nonce, pairing_file)?;

                let mut sealed_box = Vec::with_capacity(nonce.len() + ciphertext.len());
                sealed_box.extend_from_slice(&nonce);
                sealed_box.extend_from_slice(&ciphertext);

                let mut file =
                    isideload_vfs::fs::File::create(&self.bundle.bundle_dir.join(ALT_PAIRING_FILE))
                        .context(format!("Failed to create {}", ALT_PAIRING_FILE))?;
                file.write_all(&sealed_box)
                    .context(format!("Failed to write {}", ALT_PAIRING_FILE))?;
            } else {
                warn!(
                    "Pairing file is required for AltStore remote AltServer setup, but was not provided"
                )
            }

            if let Some(device_udid) = device_udid {
                self.bundle.app_info.insert(
                    "ALTDeviceId".to_string(),
                    plist::Value::String(device_udid.to_string()),
                );
            } else {
                warn!(
                    "Device UDID is required for AltStore remote AltServer setup, but was not provided"
                )
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialApp {
    SideStore,
    SideStoreLc,
    LiveContainer,
    AltStore,
    StikStore,
}

// impl display
impl std::fmt::Display for SpecialApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpecialApp::SideStore => write!(f, "SideStore"),
            SpecialApp::SideStoreLc => write!(f, "SideStore+LiveContainer"),
            SpecialApp::LiveContainer => write!(f, "LiveContainer"),
            SpecialApp::AltStore => write!(f, "AltStore"),
            SpecialApp::StikStore => write!(f, "StikStore"),
        }
    }
}
