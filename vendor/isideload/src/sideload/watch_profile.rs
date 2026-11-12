//! Watch provisioning checks. Apple's profile Platform label is an OS family,
//! not a reliable test for the SDK that built an embedded Watch executable.
//! Never rewrite profile bytes: the device must still verify Apple's CMS data.
use apple_codesign_quick::ProvisioningProfile;
use plist::{Dictionary, Value};
use rootcause::prelude::*;

use super::bundle::Bundle;

/// Validate exact bundle identity and an optional expected developer team.
/// iOS-family profiles can cover watchOS, but tvOS/macOS cannot be substituted.
pub(crate) fn validate_identity(
    profile: &Dictionary,
    bundle_id: &str,
    expected_team: Option<&str>,
) -> Result<(), Report> {
    let entitlements = profile.get("Entitlements").and_then(Value::as_dictionary)
        .ok_or_else(|| report!("Watch profile lacks Entitlements"))?;
    let identifier = entitlements.get("application-identifier").and_then(Value::as_string)
        .ok_or_else(|| report!("Watch profile lacks application-identifier"))?;
    let (prefix, suffix) = identifier.split_once('.')
        .ok_or_else(|| report!("Watch profile has malformed application-identifier"))?;
    if prefix.is_empty() || suffix != bundle_id || identifier.contains('*') {
        bail!("Watch profile bundle identity does not match {}; refusing phone-profile reuse", bundle_id);
    }
    if let Some(prefixes) = profile.get("ApplicationIdentifierPrefix") {
        if !prefixes.as_array().is_some_and(|values|
            values.iter().any(|value| value.as_string() == Some(prefix))) {
            bail!("Watch profile App ID prefix is not authorized by the profile");
        }
    }
    if let Some(team) = expected_team {
        if !profile.get("TeamIdentifier").and_then(Value::as_array).is_some_and(|values|
            values.iter().any(|value| value.as_string() == Some(team))) {
            bail!("Watch profile belongs to a different or unreported developer team");
        }
        if let Some(value) = entitlements.get("com.apple.developer.team-identifier") {
            if value.as_string() != Some(team) {
                bail!("Watch profile entitlement team does not match the selected developer team");
            }
        }
    }
    if let Some(value) = profile.get("Platform") {
        let platforms = value.as_array().ok_or_else(|| report!(
            "Watch profile Platform has an unexpected type; no upload was attempted"
        ))?;
        if platforms.is_empty() || !platforms.iter().all(|value| value.as_string().is_some()) {
            bail!("Watch profile Platform is empty or malformed; no upload was attempted");
        }
        if !platforms.iter().filter_map(Value::as_string).any(|name|
            name.eq_ignore_ascii_case("watchOS") || name.eq_ignore_ascii_case("iOS")) {
            // Only enum-like, non-private platform names are included in diagnostics.
            let labels: Vec<_> = platforms.iter().filter_map(Value::as_string)
                .map(|name| match name.to_ascii_lowercase().as_str() {
                    "tvos" => "tvOS", "osx" | "macos" => "macOS",
                    "xros" | "visionos" => "visionOS", _ => "unrecognized",
                }).collect();
            bail!("Watch profile declares an incompatible platform family ({})", labels.join(", "));
        }
    }
    Ok(())
}

pub(crate) fn validate_device_authorization(
    profile: &Dictionary,
    expected_watch_udids: &[String],
) -> Result<(), Report> {
    if expected_watch_udids.is_empty() || expected_watch_udids.iter().any(|id| id.trim().is_empty()) {
        bail!("No authenticated paired Watch identity is available for profile validation");
    }
    let devices = profile.get("ProvisionedDevices").and_then(Value::as_array)
        .ok_or_else(|| report!(
            "Watch development profile does not list provisioned devices; device authorization could not be verified"
        ))?;
    if !devices.iter().filter_map(Value::as_string).any(|device|
        expected_watch_udids.iter().any(|expected| device.eq_ignore_ascii_case(expected))) {
        bail!("Watch provisioning profile does not authorize the paired Watch. The profile was not changed; refresh device registration/profile rather than substituting an iPhone profile");
    }
    Ok(())
}

/// Preflight every Watch app/extension against a real Watch registry before the
/// phone install; the transport repeats this check with the authenticated active
/// Watch identity before sending any Watch app bytes. Ordinary phone installs do
/// not call this function. No UDID, certificates, raw profile or secrets are logged.
pub fn validate_install_profiles(
    watch_apps: &[Bundle],
    expected_watch_udids: &[String],
    expected_team: Option<&str>,
) -> Result<(), Report> {
    for root in watch_apps {
        for bundle in root.collect_app_id_bundles() {
            let bundle_id = bundle.bundle_identifier()
                .ok_or_else(|| report!("Watch application/extension lacks bundle identifier"))?;
            let data = isideload_vfs::fs::read(bundle.bundle_dir.join("embedded.mobileprovision"))
                .context("Watch application/extension lacks an embedded provisioning profile")?;
            let parsed = ProvisioningProfile::parse(&data)
                .context("Cannot parse embedded Watch provisioning profile")?;
            validate_identity(parsed.plist(), bundle_id, expected_team)?;
            validate_device_authorization(parsed.plist(), expected_watch_udids)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "watch_profile_tests.rs"]
mod tests;
