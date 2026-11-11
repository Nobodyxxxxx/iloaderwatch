use std::{path::{Path, PathBuf}, sync::Mutex, time::Duration};

use crate::{
    device::{DeviceInfoMutex, DeviceInfoWithPairing, get_provider, get_provider_from_connection, get_usbmuxd},
    error::AppError,
    operation::Operation,
    pairing::{get_sidestore_info, place_file},
    watch_transport::{PairedUsbPhone, WatchSource, WatchTransport, WATCH_HOST_NAME, contains_watch_app},
};
use idevice::provider::UsbmuxdProvider;
use isideload::{
    dev::{device_type::DeveloperDeviceType, devices::DevicesApi},
    sideload::{application::SpecialApp, bundle::Bundle, install::install_app, sideloader::Sideloader, watch_install::install_watch_apps_rsd},
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use tauri::{AppHandle, Manager, State, Window};
use tracing::info;

pub type SideloaderMutex =
    Mutex<Option<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>>>;

pub struct SideloaderGuard<'a> {
    state: &'a SideloaderMutex,
    sideloader: Option<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>>,
}

impl<'a> SideloaderGuard<'a> {
    pub fn take(state: &'a SideloaderMutex) -> Result<Self, AppError> {
        let mut guard = state.lock().unwrap();
        let sideloader = guard.take().ok_or(AppError::NotLoggedIn)?;
        Ok(Self {
            state,
            sideloader: Some(sideloader),
        })
    }

    pub fn get_mut(
        &mut self,
    ) -> &mut Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox> {
        self.sideloader
            .as_mut()
            .expect("Sideloader should be present")
    }
}

impl Drop for SideloaderGuard<'_> {
    fn drop(&mut self) {
        let mut guard = self.state.lock().unwrap();
        *guard = self.sideloader.take();
    }
}

pub async fn sideload(
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<Option<SpecialApp>, AppError> {
    let device = {
        let device_lock = device_state.lock().unwrap();
        match &*device_lock {
            Some(d) => d.clone(),
            None => return Err(AppError::NoDeviceSelected),
        }
    };

    let provider = get_provider(&device.info).await?;

    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    if contains_watch_app(Path::new(&app_path))? {
        if device.info.connection_type != "USB" {
            return Err(AppError::RemotePairing(
                "An IPA containing a Watch app requires the paired iPhone's USB connection; select USB and retry".into(),
            ));
        }
        // Keep the large signing/Watch future out of Tauri's command frame.
        return Box::pin(sideload_watch(
            sideloader.get_mut(), provider, &device, Path::new(&app_path),
        )).await;
    }

    // Official 2.4.1 phone-only path and callbacks are intentionally unchanged.
    let special = sideloader
        .get_mut()
        .install_app(
            &provider,
            app_path.into(),
            true,
            None::<fn(f32) -> std::future::Ready<()>>,
            Some(&device.pairing),
        )
        .await?;

    Ok(special)
}

async fn sideload_watch(
    sideloader: &mut Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>,
    provider: UsbmuxdProvider,
    device: &DeviceInfoWithPairing,
    original: &Path,
) -> Result<Option<SpecialApp>, AppError> {
    // The owning directory guard outlives signing and both installations. It
    // removes partial output on any error, rather than modifying the original.
    let source = WatchSource::prepare(original)?;
    if Bundle::new(source.app_path.clone())?.watch_apps().is_empty() {
        return Err(AppError::Misc(
            "The original IPA indicated a Watch app, but no valid embedded Watch bundle was found".into(),
        ));
    }
    let phone = PairedUsbPhone::authenticate(provider, &device.info.udid).await?;
    let mut transport = WatchTransport::open(&phone).await?;
    let watches = transport.paired_watch_udids(&device.info.udid).await?;

    let team = sideloader.get_team().await?;
    sideloader.get_dev_session().ensure_device_registered(
        &team, &device.info.name, &device.info.udid, None::<DeveloperDeviceType>,
    ).await?;
    for watch_udid in &watches {
        sideloader.get_dev_session().ensure_device_registered(
            &team, "Apple Watch", watch_udid, Some(DeveloperDeviceType::Watchos),
        ).await?;
    }

    // Preserve all official signing inputs, notably AltStore's encrypted
    // pairing payload, selected device ID, memory entitlement and callbacks.
    let (signed_path, special) = sideloader.sign_app(
        source.app_path.clone(),
        Some(team),
        true,
        None::<fn(f32) -> std::future::Ready<()>>,
        Some(&device.pairing),
        Some(&device.info.udid),
    ).await?;
    let signed_bundle = Bundle::new(signed_path.clone())?;
    if signed_bundle.watch_apps().is_empty() {
        return Err(AppError::Misc(
            "Signing removed the embedded Watch app; neither device was installed".into(),
        ));
    }

    // The iPhone install must complete before any Watch upload. Do not retry an
    // indeterminate phone install or uninstall an existing app on either device.
    tokio::time::timeout(Duration::from_secs(900), install_app(
        &phone, &signed_path, |progress| info!("Installing iPhone companion: {}%", progress),
    )).await.map_err(|_| AppError::DeviceComs(
        "iPhone installation timed out; its result is unknown. Watch installation was not started".into(),
    ))?.map_err(|e| AppError::DeviceComs(format!(
        "iPhone installation failed; Watch installation was not started: {e}",
    )))?;

    // Library I/O/retry deadlines are bounded and include async forwarding
    // teardown. Do NOT wrap this in timeout(): cancellation would skip teardown.
    install_watch_apps_rsd(
        &mut transport.provider,
        &mut transport.handshake,
        phone.pairing(),
        signed_bundle.watch_apps(),
        WATCH_HOST_NAME,
        |progress| info!("Installing Apple Watch companion over RSD: {}%", progress),
    ).await.map_err(|e| AppError::Misc(format!(
        "[iPhoneInstalledWatchFailed] iPhone installation completed, but Apple Watch installation failed. The installed iPhone app was kept; no existing Watch app was uninstalled. Unlock the Watch, keep it near the iPhone, and retry. Details: {e}",
    )))?;

    Ok(special)
}

#[tauri::command]
pub async fn sideload_operation(
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    app_path: String,
) -> Result<(), AppError> {
    let op = Operation::new("sideload".to_string(), &window);
    op.start("install")?;
    op.fail_if_err(
        "install",
        sideload(device_state, sideloader_state, app_path).await,
    )?;
    op.complete("install")?;
    Ok(())
}

#[tauri::command]
pub async fn install_sidestore_operation(
    handle: AppHandle,
    window: Window,
    device_state: State<'_, DeviceInfoMutex>,
    sideloader_state: State<'_, SideloaderMutex>,
    nightly: bool,
    live_container: bool,
) -> Result<(), AppError> {
    let op = Operation::new("install_sidestore".to_string(), &window);
    op.start("download")?;
    // TODO: Cache & check version to avoid re-downloading
    let (filename, url) = if live_container {
        if nightly {
            (
                "LiveContainerSideStore-Nightly.ipa",
                "https://github.com/LiveContainer/LiveContainer/releases/download/nightly/LiveContainer+SideStore.ipa",
            )
        } else {
            (
                "LiveContainerSideStore.ipa",
                "https://github.com/LiveContainer/LiveContainer/releases/latest/download/LiveContainer+SideStore.ipa",
            )
        }
    } else if nightly {
        (
            "SideStore-Nightly.ipa",
            "https://github.com/SideStore/SideStore/releases/download/nightly/SideStore.ipa",
        )
    } else {
        (
            "SideStore.ipa",
            "https://github.com/SideStore/SideStore/releases/latest/download/SideStore.ipa",
        )
    };

    let dest = handle
        .path()
        .temp_dir()
        .map_err(|e| AppError::Filesystem("Failed to get temp dir".into(), e.to_string()))?
        .join(filename);
    op.fail_if_err("download", download(url, &dest).await)?;
    op.move_on("download", "install")?;
    let device = {
        let device_guard = device_state.lock().unwrap();
        match &*device_guard {
            Some(d) => d.clone(),
            None => return op.fail("install", AppError::NoDeviceSelected),
        }
    };
    op.fail_if_err(
        "install",
        sideload(
            device_state,
            sideloader_state,
            dest.to_string_lossy().to_string(),
        )
        .await,
    )?;
    op.move_on("install", "pairing")?;
    let sidestore_info = op.fail_if_err(
        "pairing",
        get_sidestore_info(&device.info, live_container).await,
    )?;
    if let Some(info) = sidestore_info {
        let mut usbmuxd = op.fail_if_err("pairing", get_usbmuxd().await)?;

        let provider = op.fail_if_err(
            "pairing",
            get_provider_from_connection(&device.info, &mut usbmuxd).await,
        )?;

        op.fail_if_err(
            "pairing",
            place_file(device.pairing, &provider, info.bundle_id, info.path).await,
        )?;
    } else {
        return op.fail(
            "pairing",
            AppError::HouseArrest(
                "SideStore's not found".into(),
                "The device did not report SideStore's bundle ID as installed".into(),
            ),
        );
    }

    op.complete("pairing")?;
    Ok(())
}

pub async fn download(url: impl AsRef<str>, dest: &PathBuf) -> Result<(), AppError> {
    let response = reqwest::get(url.as_ref())
        .await
        .map_err(|e| AppError::Download(e.to_string()))?;
    if !response.status().is_success() {
        return Err(AppError::Download(format!(
            "Failed to download file: HTTP {}",
            response.status()
        )));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppError::Download(e.to_string()))?;
    tokio::fs::write(dest, &bytes).await.map_err(|e| {
        AppError::Filesystem("Failed to write downloaded file".into(), e.to_string())
    })?;

    Ok(())
}
