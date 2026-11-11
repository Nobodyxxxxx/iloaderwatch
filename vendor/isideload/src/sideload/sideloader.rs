use crate::{
    dev::{
        app_groups::AppGroupsApi,
        app_ids::{AppIdsApi, Profile},
        developer_session::DeveloperSession,
        device_type::DeveloperDeviceType,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        TeamSelection,
        application::{Application, SpecialApp},
        builder::{ExtensionsBehaviorSelection, MaxCertsBehavior},
        cert_identity::CertificateIdentity,
        sign,
    },
    util::{
        callbacks::{ExtensionsBehaviorCallback, MaxCertsCallback},
        device::IdeviceInfo,
        storage::SideloadingStorage,
    },
};

use std::path::PathBuf;

use apple_codesign_quick::ProvisioningProfile;
use idevice::provider::IdeviceProvider;
use plist::Dictionary;
use rootcause::{option_ext::OptionExt, prelude::*};
use tracing::info;

pub struct Sideloader<C: MaxCertsCallback, E: ExtensionsBehaviorCallback> {
    team_selection: TeamSelection,
    storage: Box<dyn SideloadingStorage>,
    dev_session: DeveloperSession,
    machine_name: String,
    apple_email: String,
    max_certs_behavior: MaxCertsBehavior<C>,
    extensions_behavior: ExtensionsBehaviorSelection<E>,
    delete_app_after_install: bool,
    team: Option<DeveloperTeam>,
}

impl<C: MaxCertsCallback, E: ExtensionsBehaviorCallback> Sideloader<C, E> {
    /// Construct a new `Sideloader` instance with the provided configuration
    ///
    /// See [`crate::sideload::SideloaderBuilder`] for more details and a more convenient way to construct a `Sideloader`.
    pub fn new(
        dev_session: DeveloperSession,
        apple_email: String,
        team_selection: TeamSelection,
        max_certs_behavior: MaxCertsBehavior<C>,
        machine_name: String,
        storage: Box<dyn SideloadingStorage>,
        extensions_behavior: ExtensionsBehaviorSelection<E>,
        delete_app_after_install: bool,
    ) -> Self {
        Sideloader {
            team_selection,
            storage,
            dev_session,
            machine_name,
            apple_email,
            max_certs_behavior,
            extensions_behavior,
            delete_app_after_install,
            team: None,
        }
    }

    /// Sign the app at the provided path and return the path to the signed app bundle (in a temp dir). To sign and install, see [`Self::install_app`].
    /// `pairing_file` is the optional pairing file to be encrypted and placed in the bundle if installing AltStore.
    /// `device_udid` is the optional device UDID to be used for AltStore pairing file injection.
    pub async fn sign_app<F, Fut>(
        &mut self,
        app_path: PathBuf,
        team: Option<DeveloperTeam>,
        // this will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
        pairing_file: Option<&[u8]>,
        device_udid: Option<&str>,
    ) -> Result<(PathBuf, Option<SpecialApp>), Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let team = match team {
            Some(t) => t,
            None => self.get_team().await?,
        };
        let cert_identity = CertificateIdentity::retrieve(
            &self.machine_name,
            &self.apple_email,
            &mut self.dev_session,
            &team,
            self.storage.as_ref(),
            &self.max_certs_behavior,
        )
        .await
        .context("Failed to retrieve certificate identity")?;

        if let Some(callback) = &progress_callback {
            callback(0.1).await;
        }

        let mut app = Application::new(app_path)?;
        let special = app.get_special_app();

        let main_bundle_id = app.main_bundle_id()?;
        let main_app_name = app.main_app_name()?;
        let main_app_id_str = format!("{}.{}", main_bundle_id, team.team_id);
        app.update_bundle_id(&main_bundle_id, &main_app_id_str)?;

        let extensions_behavior = self
            .extensions_behavior
            .behavior(app.bundle.app_extensions())
            .await?;
        let mut app_ids = app
            .register_app_ids(&extensions_behavior, &mut self.dev_session, &team)
            .await?;
        let main_app_id = match app_ids
            .iter()
            .find(|app_id| app_id.identifier == main_app_id_str)
        {
            Some(id) => id,
            None => {
                bail!(
                    "Main app ID {} not found in registered app IDs",
                    main_app_id_str
                );
            }
        }
        .clone();

        let group_identifier = format!(
            "group.{}",
            if Some(SpecialApp::SideStoreLc) == special {
                format!("com.SideStore.SideStore.{}", team.team_id)
            } else {
                main_app_id_str.clone()
            }
        );

        let watch_bundle_ids = app.watch_bundle_ids();
        // Preserve original requirements for the entire companion tree, including shared
        // phone/Watch groups. Non-companion iPhone installs keep the 0.5.2 path unchanged.
        let mut required_entitlements = std::collections::BTreeMap::new();
        if !watch_bundle_ids.is_empty() {
            for bundle in app.bundle.collect_app_id_bundles() {
                let id = bundle.bundle_identifier().ok_or_else(|| report!("Missing bundle ID"))?;
                required_entitlements.insert(id.to_string(), sign::required_entitlements(
                    bundle, &main_bundle_id, &main_app_id_str, &team.team_id,
                ).context(format!("Failed to preserve entitlements for {}", id))?);
            }
        }

        // ReuseMain phone extensions share the main App ID, so their required
        // groups must also be assigned to that ID before downloading its profile.
        let mut required_groups_by_owner: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        for (bundle, reuse_main) in app.profile_targets(&extensions_behavior) {
            let id = bundle.bundle_identifier().ok_or_else(|| report!("Missing bundle ID"))?;
            let owner = if reuse_main { main_app_id_str.as_str() } else { id };
            if let Some(groups) = required_entitlements.get(id)
                .and_then(|required| required.get("com.apple.security.application-groups"))
                .and_then(plist::Value::as_array) {
                for group in groups {
                    let group = group.as_string().ok_or_else(|| report!("Non-string application group"))?.to_string();
                    let owned = required_groups_by_owner.entry(owner.to_string()).or_default();
                    if !owned.contains(&group) { owned.push(group); }
                }
            }
        }

        let app_group = self.dev_session
            .ensure_app_group(&team, &main_app_name, &group_identifier, None).await?;
        for app_id in app_ids.iter_mut() {
            let is_watch = watch_bundle_ids.contains(&app_id.identifier);
            let platform = if is_watch { Some(DeveloperDeviceType::Watchos) } else { None };
            app_id.ensure_group_feature_for_device_type(&mut self.dev_session, &team, platform.clone()).await?;
            let mut groups = vec![if is_watch {
                self.dev_session.ensure_app_group(&team, &main_app_name, &group_identifier, platform.clone()).await?
            } else { app_group.clone() }];
            if let Some(required_groups) = required_groups_by_owner.get(&app_id.identifier) {
                for id in required_groups {
                    if groups.iter().any(|group| &group.identifier == id) { continue; }
                    groups.push(self.dev_session.ensure_app_group(&team, &main_app_name, id, platform.clone()).await?);
                }
            }
            if watch_bundle_ids.is_empty() {
                // Preserve the ordinary 0.5.2 wire format and behavior.
                self.dev_session.assign_app_group(&team, &app_group, app_id, None).await?;
            } else {
                self.dev_session.assign_app_groups(&team, &groups, app_id, platform.clone()).await?;
            }
            // This iOS-only capability must not be requested against a watchOS app ID.
            if increased_memory_limit && !is_watch {
                self.dev_session.add_increased_memory_limit(&team, app_id).await?;
            }
        }

        if let Some(callback) = &progress_callback {
            callback(0.15).await;
        }

        info!("App IDs configured");

        app.apply_special_app_behavior(
            &special,
            &group_identifier,
            &cert_identity,
            pairing_file,
            device_udid,
        )
        .await
        .context("Failed to modify app bundle")?;

        let main_provisioning_profile = self
            .dev_session
            .download_team_provisioning_profile(&team, &main_app_id, None)
            .await?;

        let mut provisioning_profiles: Vec<(String, Profile, Dictionary)> = Vec::new();

        let parsed_main = ProvisioningProfile::parse(main_provisioning_profile.encoded_profile.as_ref())?;
        let main_entitlements = parsed_main.entitlements().clone();
        if let Some(required) = required_entitlements.get(&main_app_id_str) {
            provisioning_profiles.push((main_app_id_str.clone(), main_provisioning_profile.clone(),
                sign::merge_required_entitlements(&main_entitlements, required, &main_app_id_str)?));
        }
        for (bundle, reuse_main) in app.profile_targets(&extensions_behavior) {
            let bundle_id = bundle.bundle_identifier().ok_or_else(|| report!("Missing bundle ID"))?.to_string();
            if bundle_id == main_app_id_str { continue; }
            let profile = if reuse_main {
                main_provisioning_profile.clone()
            } else {
                let id = app_ids.iter().find(|id| id.identifier == bundle_id)
                    .ok_or_else(|| report!("No registered app ID for {}", bundle_id))?;
                let platform = if watch_bundle_ids.contains(&bundle_id) {
                    Some(DeveloperDeviceType::Watchos)
                } else { None };
                self.dev_session.download_team_provisioning_profile(&team, id, platform).await
                    .context(format!("Failed to download provisioning profile for {}", bundle_id))?
            };
            let parsed = ProvisioningProfile::parse(profile.encoded_profile.as_ref())?;
            let entitlements = match required_entitlements.get(&bundle_id) {
                Some(required) => sign::merge_required_entitlements(parsed.entitlements(), required, &bundle_id)?,
                None => parsed.entitlements().clone(),
            };
            provisioning_profiles.push((bundle_id, profile, entitlements));
        }

        if let Some(callback) = &progress_callback {
            callback(0.2).await;
        }

        info!("Acquired provisioning profile");

        app.bundle.write_info_recursive()?;

        // isideload_vfs::fs::write(
        //     app.bundle.bundle_dir.join("embedded.mobileprovision"),
        //     provisioning_profile.encoded_profile.as_ref(),
        // )?;

        if let Some(callback) = &progress_callback {
            callback(0.3).await;
        }

        sign::sign(
            &mut app,
            &cert_identity,
            &main_provisioning_profile,
            &mut provisioning_profiles,
            &special,
            &team,
            progress_callback,
        )
        .await
        .context("Failed to sign app")?;

        info!("App signed!");

        Ok((app.bundle.bundle_dir.clone(), special))
    }

    #[cfg(feature = "install")]
    /// Sign and install an app to a device.
    /// This is more intended to be a helper function for simple use cases, for more complex scenarios you should call `sign_app` and `install_app` separately.
    /// `pairing_file` is the optional pairing file to be encrypted and placed in the bundle if installing AltStore.
    /// `device_udid` is the optional device UDID to be used for AltStore pairing file injection.
    pub async fn install_app<F, Fut>(
        &mut self,
        device_provider: &impl IdeviceProvider,
        app_path: PathBuf,
        // this is gross but will be replaced with proper entitlement handling later
        increased_memory_limit: bool,
        progress_callback: Option<F>,
        pairing_file: Option<&[u8]>,
    ) -> Result<Option<SpecialApp>, Report>
    where
        F: Fn(f32) -> Fut,
        Fut: Future<Output = ()>,
    {
        let device_info = IdeviceInfo::from_device(device_provider).await?;

        let team = self.get_team().await?;
        self.dev_session
            .ensure_device_registered(&team, &device_info.name, &device_info.udid, None)
            .await?;

        let (signed_app_path, special_app) = self
            .sign_app(
                app_path,
                Some(team),
                increased_memory_limit,
                progress_callback,
                pairing_file,
                Some(&device_info.udid),
            )
            .await?;

        info!("Transferring App...");

        let last_logged_progress = std::sync::Arc::new(std::sync::Mutex::new(0));
        crate::sideload::install::install_app(device_provider, &signed_app_path, |progress| {
            let mut last_progress = last_logged_progress.lock().unwrap();
            if progress >= *last_progress + 10 {
                *last_progress = progress;
                info!("Installing: {}%", progress);
            }
        })
        .await
        .context("Failed to install app on device")?;

        if self.delete_app_after_install
            && let Err(e) = isideload_vfs::fs::remove_dir_all(signed_app_path)
        {
            tracing::warn!("Failed to remove temporary signed app file: {}", e);
        }

        Ok(special_app)
    }

    /// Get the developer team according to the configured team selection behavior
    pub async fn get_team(&mut self) -> Result<DeveloperTeam, Report> {
        if let Some(team) = &self.team {
            return Ok(team.clone());
        }
        let teams = self.dev_session.list_teams().await?;
        let team = match teams.len() {
            0 => {
                bail!("No developer teams available")
            }
            1 => teams.into_iter().next().ok_or_report()?,
            _ => {
                info!(
                    "Multiple developer teams found, {} as per configuration",
                    self.team_selection
                );
                match &self.team_selection {
                    TeamSelection::First => teams.into_iter().next().ok_or_report()?,
                    TeamSelection::PromptOnce(prompt_fn)
                    | TeamSelection::PromptAlways(prompt_fn) => {
                        let selection =
                            prompt_fn(&teams).ok_or_else(|| report!("No team selected"))?;
                        teams
                            .into_iter()
                            .find(|t| t.team_id == selection)
                            .ok_or_else(|| report!("No team found with ID {}", selection))?
                    }
                }
            }
        };
        if !matches!(&self.team_selection, TeamSelection::PromptAlways(_)) {
            self.team = Some(team.clone());
        }
        Ok(team)
    }

    pub fn get_dev_session(&mut self) -> &mut DeveloperSession {
        &mut self.dev_session
    }

    pub fn get_email(&self) -> &str {
        &self.apple_email
    }
}
