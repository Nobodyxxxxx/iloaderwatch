use crate::dev::{
    app_ids::AppId,
    developer_session::DeveloperSession,
    device_type::{DeveloperDeviceType, dev_request},
    normalize_app_names,
    teams::DeveloperTeam,
};
use plist_macro::plist;
use rootcause::prelude::*;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppGroup {
    pub name: Option<String>,
    pub identifier: String,
    pub application_group: String,
}

#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
pub trait AppGroupsApi {
    fn developer_session(&mut self) -> &mut DeveloperSession;

    async fn list_app_groups(
        &mut self,
        team: &DeveloperTeam,
        device_type: impl Into<Option<DeveloperDeviceType>> + Send,
    ) -> Result<Vec<AppGroup>, Report> {
        let body = plist!(dict {
            "teamId": &team.team_id,
        });

        let (url, body) = dev_request("listApplicationGroups", device_type, body);

        let app_groups: Vec<AppGroup> = self
            .developer_session()
            .send_dev_request(
                &url,
                body,
                "applicationGroupList",
            )
            .await
            .context("Failed to list developer app groups")?;

        Ok(app_groups)
    }

    async fn add_app_group(
        &mut self,
        team: &DeveloperTeam,
        name: &str,
        identifier: &str,
        device_type: impl Into<Option<DeveloperDeviceType>> + Send,
    ) -> Result<AppGroup, Report> {
        let body = plist!(dict {
            "teamId": &team.team_id,
            "name": normalize_app_names(name),
            "identifier": identifier,
        });

        let (url, body) = dev_request("addApplicationGroup", device_type, body);

        let app_group: AppGroup = self
            .developer_session()
            .send_dev_request(
                &url,
                body,
                "applicationGroup",
            )
            .await
            .context("Failed to add developer app group")?;

        Ok(app_group)
    }

    async fn assign_app_group(
        &mut self,
        team: &DeveloperTeam,
        app_group: &AppGroup,
        app_id: &AppId,
        device_type: impl Into<Option<DeveloperDeviceType>> + Send,
    ) -> Result<(), Report> {
        let body = plist!(dict {
            "teamId": &team.team_id,
            "applicationGroups": &app_group.application_group,
            "appIdId": &app_id.app_id_id,
        });

        let (url, body) = dev_request("assignApplicationGroupToAppId", device_type, body);

        self.developer_session()
            .send_dev_request_no_response(
                &url,
                body,
            )
            .await
            .context("Failed to assign developer app group")?;

        Ok(())
    }

    /// Assign the complete group set in one request. Repeated single-group requests
    /// may replace the association, losing a companion extension's required groups.
    async fn assign_app_groups(
        &mut self,
        team: &DeveloperTeam,
        app_groups: &[AppGroup],
        app_id: &AppId,
        device_type: impl Into<Option<DeveloperDeviceType>> + Send,
    ) -> Result<(), Report> {
        let mut body = plist!(dict {
            "teamId": &team.team_id,
            "appIdId": &app_id.app_id_id,
        });
        body.insert("applicationGroups".to_string(), plist::Value::Array(
            app_groups.iter().map(|group| plist::Value::String(group.application_group.clone())).collect()
        ));
        let (url, body) = dev_request("assignApplicationGroupToAppId", device_type, body);

        self.developer_session()
            .send_dev_request_no_response(&url, body)
            .await
            .context("Failed to assign complete developer app group set")?;
        Ok(())
    }

    async fn ensure_app_group(
        &mut self,
        team: &DeveloperTeam,
        name: &str,
        identifier: &str,
        device_type: impl Into<Option<DeveloperDeviceType>> + Send,
    ) -> Result<AppGroup, Report> {
        let device_type = device_type.into();
        let groups = self.list_app_groups(team, device_type.clone()).await?;
        let matching_group = groups.iter().find(|g| g.identifier == identifier);

        if let Some(group) = matching_group {
            Ok(group.clone())
        } else {
            info!("Adding application group");
            let group = self
                .add_app_group(team, name, identifier, device_type)
                .await?;
            Ok(group)
        }
    }
}

impl AppGroupsApi for DeveloperSession {
    fn developer_session(&mut self) -> &mut DeveloperSession {
        self
    }
}
