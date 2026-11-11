#[derive(Debug, Clone)]
pub enum DeveloperDeviceType {
    Any,
    Ios,
    Tvos,
    Watchos,
}

impl DeveloperDeviceType {
    pub fn url_segment(&self) -> &'static str {
        match self {
            DeveloperDeviceType::Any => "",
            DeveloperDeviceType::Ios => "ios/",
            DeveloperDeviceType::Tvos => "tvos/",
            // The QH65B2 service routes Watch operations through the iOS
            // namespace. Watch identity belongs in the request's DTDK_Platform
            // field, not in a non-existent /watchos/ URL directory.
            DeveloperDeviceType::Watchos => "ios/",
        }
    }
}

pub fn dev_url(endpoint: &str, device_type: impl Into<Option<DeveloperDeviceType>>) -> String {
    format!(
        "https://developerservices2.apple.com/services/QH65B2/{}{}.action?clientId=XABBG36SBA",
        device_type
            .into()
            .unwrap_or(DeveloperDeviceType::Ios)
            .url_segment(),
        endpoint,
    )
}

/// Construct the URL and platform body together so Watch cannot be routed to
/// iOS without its Watch discriminator. This is shared by every platform-aware
/// devices, app-ID, profile, and app-group request.
pub(crate) fn dev_request(
    endpoint: &str,
    device_type: impl Into<Option<DeveloperDeviceType>>,
    mut body: plist::Dictionary,
) -> (String, plist::Dictionary) {
    let device_type = device_type.into();
    if matches!(device_type, Some(DeveloperDeviceType::Watchos)) {
        body.insert("DTDK_Platform".into(), plist::Value::String("watchos".into()));
    }
    (dev_url(endpoint, device_type), body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Value};

    const ENDPOINTS: &[&str] = &[
        "listDevices", "addDevice", "listAppIds", "addAppId", "updateAppId",
        "deleteAppId", "downloadTeamProvisioningProfile", "listApplicationGroups",
        "addApplicationGroup", "assignApplicationGroupToAppId",
    ];

    #[test]
    fn watch_requests_use_ios_route_and_watch_marker_in_serialized_body() {
        for endpoint in ENDPOINTS {
            let mut body = Dictionary::new();
            body.insert("teamId".into(), Value::String("SYNTHETIC-TEAM".into()));
            body.insert("deviceNumber".into(), Value::String("SYNTHETIC-WATCH-UDID".into()));
            let (url, body) = dev_request(endpoint, Some(DeveloperDeviceType::Watchos), body);
            assert_eq!(url, format!(
                "https://developerservices2.apple.com/services/QH65B2/ios/{endpoint}.action?clientId=XABBG36SBA"
            ));
            let mut wire = Vec::new();
            plist::to_writer_xml(&mut wire, &body).unwrap();
            let decoded: Dictionary = plist::from_bytes(&wire).unwrap();
            assert_eq!(decoded.get("DTDK_Platform").and_then(Value::as_string), Some("watchos"));
            assert_eq!(decoded.get("deviceNumber").and_then(Value::as_string), Some("SYNTHETIC-WATCH-UDID"));
            assert_eq!(decoded.get("teamId").and_then(Value::as_string), Some("SYNTHETIC-TEAM"));
        }
    }

    #[test]
    fn default_ios_tvos_and_any_wire_requests_are_unchanged() {
        for (platform, segment) in [
            (None, "ios/"), (Some(DeveloperDeviceType::Ios), "ios/"),
            (Some(DeveloperDeviceType::Tvos), "tvos/"), (Some(DeveloperDeviceType::Any), ""),
        ] {
            for endpoint in ENDPOINTS {
                let mut original = Dictionary::new();
                original.insert("teamId".into(), Value::String("SYNTHETIC-TEAM".into()));
                let (url, body) = dev_request(endpoint, platform.clone(), original.clone());
                assert_eq!(url, format!(
                    "https://developerservices2.apple.com/services/QH65B2/{segment}{endpoint}.action?clientId=XABBG36SBA"
                ));
                assert_eq!(body, original);
                assert!(!body.contains_key("DTDK_Platform"));
            }
        }
    }

    #[test]
    fn watch_marker_does_not_erase_profile_features_or_group_assignments() {
        let mut original = Dictionary::new();
        original.insert("appIdId".into(), Value::String("SYNTHETIC-APP-ID".into()));
        original.insert("APG3427HIY".into(), Value::Boolean(true));
        original.insert("applicationGroups".into(), Value::Array(vec![
            Value::String("GROUP-A".into()), Value::String("GROUP-B".into()),
        ]));
        let (_, body) = dev_request("assignApplicationGroupToAppId", Some(DeveloperDeviceType::Watchos), original.clone());
        for (key, value) in original { assert_eq!(body.get(&key), Some(&value)); }
        assert_eq!(body.get("DTDK_Platform").and_then(Value::as_string), Some("watchos"));
    }
}
