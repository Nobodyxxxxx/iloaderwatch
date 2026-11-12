use super::*;

fn profile(platform: Option<Value>, bundle: &str, devices: &[&str]) -> Dictionary {
    let mut entitlements = Dictionary::new();
    entitlements.insert("application-identifier".into(), format!("PREFIX.{bundle}").into());
    entitlements.insert("com.apple.developer.team-identifier".into(), "TEAM".into());
    let mut profile = Dictionary::new();
    profile.insert("Entitlements".into(), Value::Dictionary(entitlements));
    profile.insert("ApplicationIdentifierPrefix".into(), Value::Array(vec!["PREFIX".into()]));
    profile.insert("TeamIdentifier".into(), Value::Array(vec!["TEAM".into()]));
    profile.insert("ProvisionedDevices".into(), Value::Array(devices.iter().map(|s| Value::String((*s).into())).collect()));
    if let Some(platform) = platform { profile.insert("Platform".into(), platform); }
    profile
}
fn platforms(names: &[&str]) -> Option<Value> {
    Some(Value::Array(names.iter().map(|s| Value::String((*s).into())).collect()))
}
fn validate(profile: &Dictionary, bundle: &str, watch: &[&str]) -> Result<(), Report> {
    validate_identity(profile, bundle, Some("TEAM"))?;
    validate_device_authorization(profile, &watch.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
}

#[test]
fn ios_family_watch_profile_is_valid_only_for_its_exact_app_team_and_watch() {
    let p = profile(platforms(&["iOS"]), "com.phone.watch", &["WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_ok());
    assert!(validate(&p, "com.phone", &["WATCH-A"]).is_err());
    assert!(validate(&p, "com.phone.watch", &["WATCH-B"]).is_err());
    assert!(validate_identity(&p, "com.phone.watch", Some("OTHER-TEAM")).is_err());
}
#[test]
fn iphone_only_profile_cannot_authorize_a_watch_even_if_the_bundle_matches() {
    let p = profile(platforms(&["iOS"]), "com.phone.watch", &["PHONE-ONLY"]);
    assert!(validate_identity(&p, "com.phone.watch", Some("TEAM")).is_ok());
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
}
#[test]
fn exact_parent_phone_profile_is_never_reused_for_watch_or_watch_extension() {
    let p = profile(platforms(&["iOS"]), "com.phone", &["PHONE", "WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
    assert!(validate(&p, "com.phone.watch.extension", &["WATCH-A"]).is_err());
}
#[test]
fn explicit_watchos_and_multi_platform_profiles_remain_supported() {
    for names in [vec!["watchOS"], vec!["iOS", "watchOS", "xrOS"], vec!["WATCHOS"]] {
        let p = profile(platforms(&names), "com.phone.watch", &["WATCH-A"]);
        assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_ok());
    }
}
#[test]
fn other_platform_families_are_rejected_without_disclosing_profile_data() {
    for name in ["tvOS", "OSX", "macOS", "xrOS", "unknown"] {
        let p = profile(platforms(&[name]), "com.phone.watch", &["WATCH-A"]);
        let text = validate(&p, "com.phone.watch", &["WATCH-A"]).unwrap_err().to_string();
        assert!(!text.contains("WATCH-A") && !text.contains("PREFIX"));
    }
}
#[test]
fn malformed_and_empty_platform_values_do_not_pass() {
    for platform in [Value::String("iOS".into()), Value::Array(vec![]), Value::Array(vec![Value::Boolean(true)])] {
        let p = profile(Some(platform), "com.phone.watch", &["WATCH-A"]);
        assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
    }
}
#[test]
fn absent_platform_still_requires_exact_identity_team_and_watch_authorization() {
    let p = profile(None, "com.phone.watch", &["WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_ok());
    assert!(validate(&p, "com.phone.watch", &["PHONE"]).is_err());
}
#[test]
fn missing_or_empty_device_list_is_not_a_development_authorization() {
    let mut p = profile(platforms(&["iOS"]), "com.phone.watch", &[]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
    p.remove("ProvisionedDevices");
    p.insert("ProvisionsAllDevices".into(), Value::Boolean(true));
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
}
#[test]
fn actual_active_watch_must_match_even_when_registry_contains_another_watch() {
    let p = profile(platforms(&["iOS"]), "com.phone.watch", &["WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A", "WATCH-B"]).is_ok());
    assert!(validate(&p, "com.phone.watch", &["WATCH-B"]).is_err());
}
#[test]
fn unknown_target_is_not_replaced_by_a_phone_id() {
    let p = profile(platforms(&["iOS"]), "com.phone.watch", &["WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &[]).is_err());
    assert!(validate(&p, "com.phone.watch", &[" "]).is_err());
}
#[test]
fn app_id_prefix_team_and_entitlement_team_are_checked_independently() {
    let mut p = profile(platforms(&["iOS"]), "com.phone.watch", &["WATCH-A"]);
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_ok()); // Historical App ID prefix may differ from Team ID.
    p.insert("ApplicationIdentifierPrefix".into(), Value::Array(vec!["OTHER".into()]));
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
    p.insert("ApplicationIdentifierPrefix".into(), Value::Array(vec!["PREFIX".into()]));
    p.get_mut("Entitlements").unwrap().as_dictionary_mut().unwrap().insert(
        "com.apple.developer.team-identifier".into(), "OTHER".into());
    assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
}
#[test]
fn wildcard_or_suffix_collision_cannot_match_a_watch_identity() {
    for id in ["com.phone.*", "extra.com.phone.watch", "com.phone.watch.more"] {
        let p = profile(platforms(&["iOS"]), id, &["WATCH-A"]);
        assert!(validate(&p, "com.phone.watch", &["WATCH-A"]).is_err());
    }
}
