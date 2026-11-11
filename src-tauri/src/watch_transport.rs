//! On-demand USB -> CoreDeviceProxy -> userspace TCP/RSD transport for Watch IPAs.
//! No saved-login, Wi-Fi discovery, renewal, or platform tunnel driver is involved.
use std::{
    fmt,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};

use idevice::{
    Idevice, IdeviceError, IdeviceService, RsdService,
    companion_proxy::CompanionProxy,
    core_device_proxy::CoreDeviceProxy,
    lockdown::LockdownClient,
    pairing_file::PairingFile,
    provider::{IdeviceProvider, UsbmuxdProvider},
    rsd::RsdHandshake,
    tcp::handle::AdapterHandle,
};

use crate::error::AppError;

pub(crate) const WATCH_HOST_NAME: &str = "iloader";
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(30);
const COMPANION_RSD_SERVICE: &str = "com.apple.companion_proxy.shim.remote";

fn transport_error(context: &str, error: impl fmt::Display) -> AppError {
    AppError::RemotePairing(format!("{context}: {error}"))
}

/// 0.1.68's UsbmuxdProvider has no with_pairing_file() method. Attach one
/// immutable record explicitly so all service sessions use the verified identity.
/// Never include the pairing file in Debug/log output.
pub(crate) struct PairedUsbPhone {
    inner: UsbmuxdProvider,
    pairing: PairingFile,
}

impl fmt::Debug for PairedUsbPhone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedUsbPhone").finish_non_exhaustive()
    }
}

impl PairedUsbPhone {
    pub(crate) async fn authenticate(
        inner: UsbmuxdProvider,
        expected_udid: &str,
    ) -> Result<Self, AppError> {
        if expected_udid.is_empty() || inner.udid != expected_udid {
            return Err(transport_error("USB phone identity check failed", "selection changed"));
        }
        let pairing = tokio::time::timeout(IO_TIMEOUT, inner.get_pairing_file())
            .await
            .map_err(|e| transport_error("Reading the iPhone pairing record timed out", e))?
            .map_err(|e| transport_error("Unable to read the existing iPhone pairing record", e))?;
        let phone = Self { inner, pairing };
        tokio::time::timeout(IO_TIMEOUT, async {
            // LockdownClient::connect does not start a session. Other
            // IdeviceService::connect implementations do so automatically.
            let mut lockdown = LockdownClient::connect(&phone).await?;
            lockdown.start_session(&phone.pairing).await?;
            let identity = lockdown.get_value(Some("UniqueDeviceID"), None).await?;
            if identity.as_string() != Some(expected_udid) {
                return Err(IdeviceError::UnexpectedResponse(
                    "Authenticated iPhone does not match the selected device".into(),
                ));
            }
            Ok::<(), IdeviceError>(())
        })
        .await
        .map_err(|e| transport_error("Authenticating the selected USB iPhone timed out", e))?
        .map_err(|e| transport_error("Unable to authenticate the selected USB iPhone", e))?;
        Ok(phone)
    }

    pub(crate) fn pairing(&self) -> &PairingFile {
        &self.pairing
    }
}

impl IdeviceProvider for PairedUsbPhone {
    fn connect(
        &self,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Idevice, IdeviceError>> + Send>> {
        self.inner.connect(port)
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn get_pairing_file(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PairingFile, IdeviceError>> + Send>> {
        let pairing = self.pairing.clone();
        Box::pin(async move { Ok(pairing) })
    }
}

/// Own the handle for the entire install; dropping it closes the software tunnel.
/// There are no detached host tasks, OS routes, TUN adapters, or forwarding ports
/// here. Watch forwarding lifetimes/teardown belong to install_watch_apps_rsd.
pub(crate) struct WatchTransport {
    pub(crate) provider: AdapterHandle,
    pub(crate) handshake: RsdHandshake,
}

impl WatchTransport {
    pub(crate) async fn open(phone: &PairedUsbPhone) -> Result<Self, AppError> {
        tokio::time::timeout(TUNNEL_TIMEOUT, async {
            // This service authenticates through lockdown using the existing USB
            // pair record; do not generate/persist a second RemotePairing identity.
            let proxy = CoreDeviceProxy::connect(phone).await?;
            let rsd_port = proxy.tunnel_info().server_rsd_port;
            let adapter = proxy.create_software_tunnel()?;
            let mut provider = adapter.to_async_handle();
            let stream = provider.connect(rsd_port).await?;
            let handshake = RsdHandshake::new(stream).await?;
            if !handshake.services.contains_key(COMPANION_RSD_SERVICE) {
                return Err(IdeviceError::UnexpectedResponse(
                    "USB RSD did not advertise CompanionProxy; unlock the iPhone, enable Developer Mode, and reconnect over USB".into(),
                ));
            }
            Ok::<Self, IdeviceError>(Self { provider, handshake })
        })
        .await
        .map_err(|e| transport_error("Opening the USB Watch RSD tunnel timed out", e))?
        .map_err(|e| transport_error("Unable to open the USB Watch RSD tunnel", e))
    }

    /// Read-only registry query, at most three attempts while the paired Watch
    /// comes online. Never substitute the phone's UDID or invent a Watch UDID.
    pub(crate) async fn paired_watch_udids(
        &mut self,
        phone_udid: &str,
    ) -> Result<Vec<String>, AppError> {
        for attempt in 0..3 {
            let registry = tokio::time::timeout(IO_TIMEOUT, async {
                let mut companion = CompanionProxy::connect_rsd(
                    &mut self.provider,
                    &mut self.handshake,
                )
                .await?;
                companion.get_device_registry().await
            })
            .await
            .map_err(|e| transport_error("Reading the paired Watch registry timed out", e))?
            .map_err(|e| transport_error("Unable to read the paired Watch registry over RSD", e))?;
            let watches = validate_watch_registry(registry, phone_udid)?;
            if !watches.is_empty() {
                return Ok(watches);
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
        Err(transport_error(
            "No paired Apple Watch was reported by the iPhone",
            "unlock the Watch and keep it near the USB-connected iPhone",
        ))
    }
}

fn validate_watch_registry(registry: Vec<String>, phone_udid: &str) -> Result<Vec<String>, AppError> {
    let mut watches: Vec<String> = Vec::new();
    for udid in registry {
        if udid.trim().is_empty() || udid.trim() != udid || udid.eq_ignore_ascii_case(phone_udid) {
            return Err(transport_error(
                "Invalid paired Watch registry",
                "the registry contained an empty, malformed, or iPhone device identifier",
            ));
        }
        if !watches.iter().any(|existing| existing.eq_ignore_ascii_case(&udid)) {
            watches.push(udid);
        }
    }
    Ok(watches)
}

/// Only inspect archive names / a local Watch directory here. Ordinary IPAs must
/// continue through Sideloader::install_app without opening any Watch service.
pub(crate) fn contains_watch_app(path: &Path) -> Result<bool, AppError> {
    if path.is_dir() {
        let watch = path.join("Watch");
        if !watch.is_dir() {
            return Ok(false);
        }
        for entry in std::fs::read_dir(watch)
            .map_err(|e| source_error("Cannot read the embedded Watch directory", e))?
        {
            let entry = entry.map_err(|e| source_error("Cannot read a Watch directory entry", e))?;
            if entry.path().extension().is_some_and(|ext| ext == "app")
                && entry.file_type().map_err(|e| source_error("Cannot inspect a Watch bundle", e))?.is_dir()
            {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let file = std::fs::File::open(path)
        .map_err(|e| source_error("Cannot open the original IPA", e))?;
    let archive = zip::ZipArchive::new(file)
        .map_err(|e| source_error("Cannot inspect the original IPA", e))?;
    let has_watch = archive.file_names().any(is_watch_archive_entry);
    Ok(has_watch)
}

fn is_watch_archive_entry(name: &str) -> bool {
    if name.contains('\\') { return false; }
    let parts: Vec<_> = name.trim_end_matches('/').split('/').collect();
    parts.len() >= 4
        && parts[0] == "Payload"
        && parts[1].ends_with(".app") && parts[1] != ".app"
        && parts[2] == "Watch"
        && parts[3].ends_with(".app") && parts[3] != ".app"
        && parts.iter().all(|part| !part.is_empty() && *part != "." && *part != "..")
}

fn source_error(context: &str, error: impl fmt::Display) -> AppError {
    AppError::Misc(format!("{context}: {error}"))
}

/// Sign only an owned extraction/copy: no changes to the user's IPA/.app. Keeping
/// this guard across every await cleans partially signed content on failure and
/// cancellation too, rather than only cleaning after a successful installation.
pub(crate) struct WatchSource {
    _directory: tempfile::TempDir,
    pub(crate) app_path: PathBuf,
}

impl WatchSource {
    pub(crate) fn prepare(original: &Path) -> Result<Self, AppError> {
        let directory = tempfile::Builder::new().prefix("iloader-watch-").tempdir()
            .map_err(|e| source_error("Cannot create a private Watch signing directory", e))?;
        let app_path = if original.is_dir() {
            let target = directory.path().join("Companion.app");
            copy_app_tree(original, &target, 0)?;
            target
        } else {
            let file = std::fs::File::open(original)
                .map_err(|e| source_error("Cannot open the original Watch IPA", e))?;
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|e| source_error("Cannot read the original Watch IPA", e))?;
            archive.extract(directory.path())
                .map_err(|e| source_error("Cannot extract the original Watch IPA", e))?;
            let payload = directory.path().join("Payload");
            let mut apps = Vec::new();
            for entry in std::fs::read_dir(&payload)
                .map_err(|e| source_error("Watch IPA has no readable Payload", e))?
            {
                let entry = entry.map_err(|e| source_error("Cannot read Payload entry", e))?;
                if entry.path().extension().is_some_and(|ext| ext == "app")
                    && entry.file_type().map_err(|e| source_error("Cannot inspect Payload entry", e))?.is_dir()
                {
                    apps.push(entry.path());
                }
            }
            if apps.len() != 1 {
                return Err(AppError::Misc("Watch IPA must contain exactly one top-level Payload/*.app".into()));
            }
            apps.remove(0)
        };
        Ok(Self { _directory: directory, app_path })
    }
}

fn copy_app_tree(source: &Path, target: &Path, depth: usize) -> Result<(), AppError> {
    if depth > 128 {
        return Err(AppError::Misc("Watch app directory nesting exceeds 128 levels".into()));
    }
    std::fs::create_dir(target)
        .map_err(|e| source_error("Cannot create temporary app directory", e))?;
    for entry in std::fs::read_dir(source)
        .map_err(|e| source_error("Cannot read source app directory", e))?
    {
        let entry = entry.map_err(|e| source_error("Cannot read source app entry", e))?;
        let kind = entry.file_type().map_err(|e| source_error("Cannot inspect source app entry", e))?;
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_app_tree(&entry.path(), &destination, depth + 1)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), destination)
                .map_err(|e| source_error("Cannot copy app into signing workspace", e))?;
        } else {
            return Err(AppError::Misc("Watch app source contains a symlink or unsupported file type; use the original IPA instead".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_probe_requires_an_embedded_watch_app() {
        assert!(is_watch_archive_entry("Payload/Phone.app/Watch/Companion.app/Info.plist"));
        assert!(is_watch_archive_entry("Payload/Phone.app/Watch/Companion.app/"));
        for other in [
            "Payload/Phone.app/Info.plist", "Payload/Phone.app/Watch/readme.txt",
            "Payload/Phone.app/PlugIns/Companion.app/Info.plist",
            "Payload/Phone.app/Watch/../Bad.app/Info.plist",
            "Payload/Phone.app/Watch/.app/Info.plist",
            "Payload/Phone.app/Watch/Fake.app/../../Info.plist",
            "Payload/Phone.app/Watch//Companion.app/Info.plist",
            "Elsewhere/Phone.app/Watch/Companion.app/Info.plist",
        ] { assert!(!is_watch_archive_entry(other), "{other}"); }
    }

    #[test]
    fn directory_probe_ignores_phone_only_and_non_app_watch_content() {
        let original = tempfile::tempdir().unwrap();
        assert!(!contains_watch_app(original.path()).unwrap());
        let watch = original.path().join("Watch");
        std::fs::create_dir(&watch).unwrap();
        std::fs::write(watch.join("readme.txt"), b"not an app").unwrap();
        assert!(!contains_watch_app(original.path()).unwrap());
        std::fs::create_dir(watch.join("Companion.app")).unwrap();
        assert!(contains_watch_app(original.path()).unwrap());
    }

    #[test]
    fn registry_never_substitutes_the_phone_and_deduplicates() {
        assert!(validate_watch_registry(vec!["PHONE".into()], "phone").is_err());
        assert!(validate_watch_registry(vec![" ".into()], "phone").is_err());
        assert!(validate_watch_registry(vec![" watch".into()], "phone").is_err());
        assert!(validate_watch_registry(Vec::new(), "phone").unwrap().is_empty());
        assert_eq!(validate_watch_registry(vec!["watch-a".into(), "WATCH-A".into(), "watch-b".into()], "phone").unwrap(), vec!["watch-a", "watch-b"]);
    }

    #[test]
    fn private_app_copy_does_not_mutate_the_original_and_is_removed() {
        let original = tempfile::tempdir().unwrap();
        std::fs::write(original.path().join("Info.plist"), b"original").unwrap();
        let source = WatchSource::prepare(original.path()).unwrap();
        let copy = source.app_path.clone();
        std::fs::write(copy.join("Info.plist"), b"signed").unwrap();
        assert_eq!(std::fs::read(original.path().join("Info.plist")).unwrap(), b"original");
        drop(source);
        assert!(!copy.exists());
    }
}
