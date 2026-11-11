use std::collections::BTreeMap;

#[path = "signing_entitlements.rs"]
mod required;

pub(crate) fn required_entitlements(
    bundle: &crate::sideload::bundle::Bundle,
    old: &str,
    new: &str,
    team: &str,
) -> Result<Dictionary, Report> {
    let executable = bundle.app_info.get("CFBundleExecutable").and_then(plist::Value::as_string)
        .ok_or_else(|| report!("Missing CFBundleExecutable in {}", bundle.bundle_dir.display()))?;
    let data = isideload_vfs::fs::read(bundle.bundle_dir.join(executable))
        .context("Failed to read original executable entitlements")?;
    remap_required_entitlements(required::extract(&data)?, old, new, team)
}

fn remap_required_entitlements(mut entitlements: Dictionary, old: &str, new: &str, team: &str) -> Result<Dictionary, Report> {
    if let Some(groups) = entitlements.get_mut("com.apple.security.application-groups") {
        let groups = groups.as_array_mut().ok_or_else(|| report!("Application groups are not an array"))?;
        for group in groups {
            let original = group.as_string().ok_or_else(|| report!("Non-string application group"))?;
            let mapped = if original.ends_with(&format!(".{}", team)) {
                original.to_string()
            } else { format!("{}.{}", original, team) };
            *group = plist::Value::String(mapped);
        }
    }
    if let Some(groups) = entitlements.get_mut("keychain-access-groups") {
        let groups = groups.as_array_mut().ok_or_else(|| report!("Keychain groups are not an array"))?;
        for group in groups {
            let original = group.as_string().ok_or_else(|| report!("Non-string keychain group"))?;
            let suffix = original.split_once('.').map(|(_, suffix)| suffix).unwrap_or(original);
            let mapped = match suffix.strip_prefix(old) {
                Some(tail) if tail.is_empty() || tail.starts_with('.') => format!("{}{}", new, tail),
                _ => suffix.to_string(),
            };
            *group = plist::Value::String(format!("{}.{}", team, mapped));
        }
    }
    Ok(entitlements)
}

pub(crate) fn merge_required_entitlements(
    profile: &Dictionary,
    requested: &Dictionary,
    bundle_id: &str,
) -> Result<Dictionary, Report> {
    required::merge(profile, requested, bundle_id)
}


use apple_codesign_quick::{
    BundleSigningSettings, ProvisioningProfile, RustCryptoCmsSigner, sign_bundle,
};

use plist::Dictionary;
use rootcause::prelude::*;
use tracing::warn;

use crate::{
    dev::{app_ids::Profile, teams::DeveloperTeam},
    sideload::{
        application::{Application, SpecialApp},
        cert_identity::CertificateIdentity,
    },
};

pub async fn sign<F, Fut>(
    app: &mut Application,
    cert_identity: &CertificateIdentity,
    main_provisioning_profile: &Profile,
    all_profiles: &mut Vec<(String, Profile, Dictionary)>,
    special: &Option<SpecialApp>,
    team: &DeveloperTeam,
    progress_callback: Option<F>,
) -> Result<(), Report>
where
    F: Fn(f32) -> Fut,
    Fut: Future<Output = ()>,
{
    // Guard against a caller accidentally associating a phone profile with a Watch ID.
    for id in app.watch_bundle_ids() {
        let (_, profile, _) = all_profiles.iter().find(|(candidate, _, _)| candidate == &id)
            .ok_or_else(|| report!("Explicit watchOS provisioning profile required for {}", id))?;
        let parsed = ProvisioningProfile::parse(profile.encoded_profile.as_ref())?;
        required::validate_watch_profile(parsed.plist(), &id)?;
    }
    let profile = ProvisioningProfile::parse(main_provisioning_profile.encoded_profile.as_ref())?;
    let certificate_chain = cert_identity.profile_to_certificate_chain(&profile)?;

    let signer = RustCryptoCmsSigner::new(
        cert_identity.private_key.clone(),
        cert_identity.certificate.clone(),
        certificate_chain,
    );
    if let Some(callback) = &progress_callback {
        callback(0.4).await;
    }

    let mut entitlements = all_profiles.iter()
        .find(|(id, _, _)| Some(id.as_str()) == app.bundle.bundle_identifier())
        .map(|(_, _, entitlements)| entitlements.clone())
        .unwrap_or_else(|| profile.entitlements().clone());
    if matches!(
        special,
        Some(SpecialApp::SideStoreLc) | Some(SpecialApp::LiveContainer)
    ) {
        let mut keychain_access = vec![plist::Value::String(format!(
            "{}.com.kdt.livecontainer.shared",
            team.team_id
        ))];

        for number in 1..128 {
            keychain_access.push(plist::Value::String(format!(
                "{}.com.kdt.livecontainer.shared.{}",
                team.team_id, number
            )));
        }

        entitlements.insert(
            "keychain-access-groups".to_string(),
            plist::Value::Array(keychain_access.clone()),
        );

        let liveprocess_profile = all_profiles
            .iter_mut()
            .find(|(bundle_id, _, _)| bundle_id.ends_with("LiveProcess"));
        if let Some((_, _, liveprocess_entitlements)) = liveprocess_profile {
            liveprocess_entitlements.insert(
                "keychain-access-groups".to_string(),
                plist::Value::Array(keychain_access),
            );
        } else {
            warn!("Could not find LiveProcess profile");
        }
    }

    let mut settings = BundleSigningSettings::new(&team.team_id, entitlements, Some(&signer));
    settings.embedded_mobileprovision = Some(main_provisioning_profile.encoded_profile.as_ref());

    settings.embedded_mobileprovisions_by_bundle_id = all_profiles
        .iter()
        .map(|(bundle_id, data, _)| (bundle_id.clone(), data.encoded_profile.as_ref()))
        .collect::<BTreeMap<_, _>>();
    settings.entitlements_by_bundle_id = all_profiles
        .iter()
        // The root uses main_entitlements, including the preserved SpecialApp overrides.
        .filter(|(id, _, _)| Some(id.as_str()) != app.bundle.bundle_identifier())
        .map(|(bundle_id, _, entitlements)| (bundle_id.clone(), entitlements.clone()))
        .collect();

    if let Some(callback) = &progress_callback {
        callback(0.5).await;
    }

    // apple-codesign-quick 0.1 scans Frameworks/PlugIns, not Watch. Sign every
    // Watch root inside-out before the phone seals its resources. Reuse the SAME
    // signer/settings so repeated library signing is deterministic (same CMS time).
    // Per-ID overrides are mandatory, even when the phone extension callback said ReuseMain.
    let watch_ids = app.watch_bundle_ids();
    let bundles = app.bundle.collect_bundles_sorted();
    for bundle in bundles.iter().filter(|bundle|
        bundle.bundle_dir.extension().is_some_and(|ext| ext == "app")
            && bundle.bundle_identifier().is_some_and(|id| watch_ids.contains(id))) {
        let id = bundle.bundle_identifier().ok_or_else(|| report!("Missing Watch bundle ID"))?;
        if !settings.embedded_mobileprovisions_by_bundle_id.contains_key(id)
            || !settings.entitlements_by_bundle_id.contains_key(id) {
            bail!("Explicit watchOS profile and entitlements required for {}", id);
        }
        sign_bundle(&bundle.bundle_dir, &settings)
            .context(format!("Failed to sign Watch companion {}", id))?;
    }
    // The parent signer also visits dylibs inside Watch as resources. Verify that
    // deterministic repeat signing did not mutate a previously sealed Watch library.
    // Never return success with stale nested CodeResources if the backend changes.
    use sha2::Digest as _;
    let watch_roots: Vec<_> = bundles.iter().filter(|bundle|
        bundle.bundle_dir.extension().is_some_and(|ext| ext == "app")
            && bundle.bundle_identifier().is_some_and(|id| watch_ids.contains(id)))
        .map(|bundle| bundle.bundle_dir.clone()).collect();
    let mut watch_library_hashes = BTreeMap::new();
    for bundle in bundles.iter().filter(|bundle|
        bundle.bundle_dir.extension().is_some_and(|ext| ext == "dylib")
            && watch_roots.iter().any(|root| bundle.bundle_dir.starts_with(root))) {
        let data = isideload_vfs::fs::read(&bundle.bundle_dir)?;
        watch_library_hashes.insert(bundle.bundle_dir.clone(), sha2::Sha256::digest(&data).to_vec());
    }
    sign_bundle(&app.bundle.bundle_dir, &settings)?;
    for (path, before) in watch_library_hashes {
        let data = isideload_vfs::fs::read(&path)?;
        if sha2::Sha256::digest(&data).to_vec() != before {
            bail!("Parent signing changed sealed Watch library {}; refusing an invalid companion signature", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_groups_map_identically_for_phone_and_watch() {
        let mut source = Dictionary::new();
        source.insert("com.apple.security.application-groups".into(), plist::Value::Array(vec!["group.shared".into(), "group.second".into()]));
        source.insert("keychain-access-groups".into(), plist::Value::Array(vec!["OLD.com.phone.shared".into()]));
        let phone = remap_required_entitlements(source.clone(), "com.phone", "com.phone.TEAM", "TEAM").unwrap();
        let watch = remap_required_entitlements(source, "com.phone", "com.phone.TEAM", "TEAM").unwrap();
        assert_eq!(phone, watch);
        assert_eq!(phone["com.apple.security.application-groups"].as_array().unwrap(), &vec![plist::Value::String("group.shared.TEAM".into()), plist::Value::String("group.second.TEAM".into())]);
        assert_eq!(phone["keychain-access-groups"].as_array().unwrap()[0].as_string(), Some("TEAM.com.phone.TEAM.shared"));
    }
}
