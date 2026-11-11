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
            DeveloperDeviceType::Watchos => "watchos/",
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn watch_and_default_phone_requests_keep_distinct_platform_endpoints() {
        for endpoint in ["listDevices", "addDevice", "listAppIds", "addAppId", "updateAppId", "downloadTeamProvisioningProfile", "assignApplicationGroupToAppId"] {
            assert!(dev_url(endpoint, Some(DeveloperDeviceType::Watchos)).contains(&format!("/watchos/{}.action", endpoint)));
            assert_eq!(dev_url(endpoint, None), dev_url(endpoint, Some(DeveloperDeviceType::Ios)));
        }
    }
}
