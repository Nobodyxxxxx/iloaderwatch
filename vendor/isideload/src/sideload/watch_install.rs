use idevice::{
    Idevice, IdeviceService, RsdService,
    pairing_file::PairingFile,
    provider::{IdeviceProvider, RsdProvider},
    rsd::RsdHandshake,
    services::{companion_proxy::CompanionProxy, lockdown::LockdownClient},
};
use plist::{Dictionary, Value};
use rootcause::{option_ext::OptionExt, prelude::*};
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{info, warn};

use crate::{SideloadError as Error, sideload::bundle::Bundle};

const WATCH_LOCKDOWN_PORT: u16 = 62078;
const WATCH_LOCKDOWN_SERVICE: &str = "com.apple.mobile.lockdownd";
const WATCH_ZIP_SERVICE: &str = "com.apple.streaming_zip_conduit";
const WATCH_FORWARD_CONNECT_ATTEMPTS: usize = 20;
const WATCH_FORWARD_CONNECT_DELAY_MS: u64 = 50;
const WATCH_INSTALL_ATTEMPTS: usize = 7;
const WATCH_INSTALL_INITIAL_RETRY_DELAY_MS: u64 = 400;
const WATCH_INSTALL_MAX_RETRY_DELAY_MS: u64 = 2500;
// Bounds include the library's otherwise unbounded pair() trust-dialog loop.
const WATCH_IO_TIMEOUT: Duration = Duration::from_secs(15);
const WATCH_PAIR_TIMEOUT: Duration = Duration::from_secs(90);
const WATCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const WATCH_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);
const WATCH_INSTALL_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_PLIST_BYTES: usize = 1024 * 1024;
const MAX_BUNDLE_DEPTH: usize = 128;
const CENTRAL_DIRECTORY_HEADER: &[u8] = &[0x50, 0x4b, 0x01, 0x02];
const ZIP_EXTRA: &[u8] = &[
    0x55, 0x54, 0x0d, 0x00, 0x07, 0xf3, 0xa2, 0xec, 0x60, 0xf6, 0xa2, 0xec, 0x60, 0xf3,
    0xa2, 0xec, 0x60, 0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0xf5, 0x01, 0x00, 0x00, 0x04,
    0x14, 0x00, 0x00, 0x00,
];

/// Install already-signed Watch bundles without rewriting signatures or uninstalling apps.
/// Pairing records are ephemeral and are never logged or persisted by this module.
/// Forwarding teardown is attempted on every normal/error/timeout return. As with other
/// async I/O APIs, callers must await completion: dropping this future cannot await teardown.
pub async fn install_watch_apps(
    device_provider: &impl IdeviceProvider,
    watch_apps: &[Bundle],
    host_name: &str,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<(), Report> {
    if watch_apps.is_empty() {
        return Ok(());
    }

    let iphone_pairing = watch_io_for(WATCH_IO_TIMEOUT, device_provider
        .get_pairing_file())
        .await
        .map_err(Error::IdeviceError)?;

    let forwarded_lockdown_port = start_watch_forward(device_provider, WATCH_LOCKDOWN_PORT, WATCH_LOCKDOWN_SERVICE).await?;

    let result = async {
        let watch_connection = connect_forwarded_watch_port(
            device_provider,
            forwarded_lockdown_port,
            "lockdown",
        )
        .await?;
        let mut watch_lockdown = LockdownClient::new(watch_connection);

        let watch_pairing = watch_io_for(WATCH_PAIR_TIMEOUT, watch_lockdown
            .pair(
                iphone_pairing.host_id.clone(),
                iphone_pairing.system_buid.clone(),
                Some(host_name),
            ))
            .await
            .map_err(Error::IdeviceError)
            .context("Failed to pair with the Apple Watch through companion proxy")?;

        let legacy = watch_io_for(WATCH_IO_TIMEOUT, watch_lockdown
            .start_session(&watch_pairing))
            .await
            .map_err(Error::IdeviceError)
            .context("Failed to start Apple Watch lockdown session")?;

        for watch_app in watch_apps {
            install_watch_app_with_retry(
                device_provider,
                &mut watch_lockdown,
                &watch_pairing,
                legacy,
                watch_app,
                &progress_callback,
            )
            .await?;
        }

        Ok(())
    }
    .await;

    stop_watch_forward(device_provider, WATCH_LOCKDOWN_PORT).await;

    result
}

/// RSD counterpart. CompanionProxy performs the shim RSD check-in; the forwarded
/// sockets carry Watch lockdown/zip traffic directly, NOT an additional RSD check-in.
pub async fn install_watch_apps_rsd(
    rsd_provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    iphone_pairing: &PairingFile,
    watch_apps: &[Bundle],
    host_name: &str,
    progress_callback: impl Fn(u64) + Send + Sync,
) -> Result<(), Report> {
    if watch_apps.is_empty() {
        return Ok(());
    }

    let forwarded_lockdown_port = start_watch_forward_rsd(rsd_provider, handshake, WATCH_LOCKDOWN_PORT, WATCH_LOCKDOWN_SERVICE).await?;

    let result = async {
        let watch_connection = connect_forwarded_watch_port_rsd(
            rsd_provider,
            forwarded_lockdown_port,
            "lockdown",
        )
        .await?;
        let mut watch_lockdown = LockdownClient::new(watch_connection);

        let watch_pairing = watch_io_for(WATCH_PAIR_TIMEOUT, watch_lockdown
            .pair(
                iphone_pairing.host_id.clone(),
                iphone_pairing.system_buid.clone(),
                Some(host_name),
            ))
            .await
            .map_err(Error::IdeviceError)
            .context("Failed to pair with the Apple Watch through RSD companion proxy")?;

        let legacy = watch_io_for(WATCH_IO_TIMEOUT, watch_lockdown
            .start_session(&watch_pairing))
            .await
            .map_err(Error::IdeviceError)
            .context("Failed to start Apple Watch lockdown session over RSD")?;

        for watch_app in watch_apps {
            install_watch_app_with_retry_rsd(
                rsd_provider,
                handshake,
                &mut watch_lockdown,
                &watch_pairing,
                legacy,
                watch_app,
                &progress_callback,
            )
            .await?;
        }

        Ok(())
    }
    .await;

    stop_watch_forward_rsd(rsd_provider, handshake, WATCH_LOCKDOWN_PORT).await;

    result
}

async fn connect_forwarded_watch_port(
    device_provider: &impl IdeviceProvider,
    forwarded_port: u16,
    service: &str,
) -> Result<Idevice, Report> {
    for attempt in 1..=WATCH_FORWARD_CONNECT_ATTEMPTS {
        match watch_io_for(WATCH_CONNECT_TIMEOUT, device_provider.connect(forwarded_port)).await {
            Ok(connection) => {
                if attempt > 1 {
                    info!(
                        "Connected to Apple Watch {} on forwarded port {} after {} attempts",
                        service, forwarded_port, attempt
                    );
                }
                return Ok(connection);
            }
            Err(_error) if attempt < WATCH_FORWARD_CONNECT_ATTEMPTS => {
                warn!(
                    "Apple Watch {} forwarded port {} is not ready (attempt {}/{})",
                    service,
                    forwarded_port,
                    attempt,
                    WATCH_FORWARD_CONNECT_ATTEMPTS
                );
                tokio::time::sleep(Duration::from_millis(
                    WATCH_FORWARD_CONNECT_DELAY_MS,
                ))
                .await;
            }
            Err(_error) => {
                bail!(
                    "Failed to connect to Apple Watch {} on forwarded iPhone port {} after {} attempts",
                    service,
                    forwarded_port,
                    WATCH_FORWARD_CONNECT_ATTEMPTS
                );
            }
        }
    }

    unreachable!("bounded forwarded-port retry loop must return")
}

async fn connect_forwarded_watch_port_rsd(
    rsd_provider: &mut impl RsdProvider,
    forwarded_port: u16,
    service: &str,
) -> Result<Idevice, Report> {
    for attempt in 1..=WATCH_FORWARD_CONNECT_ATTEMPTS {
        match watch_io_for(WATCH_CONNECT_TIMEOUT, rsd_provider.connect_to_service_port(forwarded_port)).await {
            Ok(stream) => {
                if attempt > 1 {
                    info!(
                        "Connected to Apple Watch {} over RSD on forwarded port {} after {} attempts",
                        service, forwarded_port, attempt
                    );
                }
                return Ok(Idevice::new(stream, "isideload-watch-rsd"));
            }
            Err(_error) if attempt < WATCH_FORWARD_CONNECT_ATTEMPTS => {
                warn!(
                    "Apple Watch {} RSD forwarded port {} is not ready (attempt {}/{})",
                    service,
                    forwarded_port,
                    attempt,
                    WATCH_FORWARD_CONNECT_ATTEMPTS
                );
                tokio::time::sleep(Duration::from_millis(
                    WATCH_FORWARD_CONNECT_DELAY_MS,
                ))
                .await;
            }
            Err(_error) => {
                bail!(
                    "Failed to connect to Apple Watch {} on RSD forwarded iPhone port {} after {} attempts",
                    service,
                    forwarded_port,
                    WATCH_FORWARD_CONNECT_ATTEMPTS
                );
            }
        }
    }

    unreachable!("bounded RSD forwarded-port retry loop must return")
}

async fn install_watch_app_with_retry(
    device_provider: &impl IdeviceProvider,
    watch_lockdown: &mut LockdownClient,
    watch_pairing: &PairingFile,
    legacy: bool,
    watch_app: &Bundle,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    let bundle_id = watch_app
        .bundle_identifier()
        .ok_or_report()
        .context("Watch app is missing CFBundleIdentifier")?;

    for attempt in 1..=WATCH_INSTALL_ATTEMPTS {
        match install_watch_app_zip_conduit(
            device_provider,
            watch_lockdown,
            watch_pairing,
            legacy,
            watch_app,
            progress_callback,
        )
        .await
        {
            Ok(()) => {
                if attempt > 1 {
                    info!(
                        "Apple Watch app {bundle_id} installed/updated after {attempt} attempts"
                    );
                }
                return Ok(());
            }
            Err(error)
                if watch_retry_delay(attempt, is_watch_coordinator_conflict(&error)).is_some() =>
            {
                let retry_delay_ms = watch_retry_delay(attempt, true).unwrap().as_millis() as u64;
                warn!(
                    "Apple Watch install coordinator still busy for {bundle_id} (attempt {attempt}/{WATCH_INSTALL_ATTEMPTS}); retrying with a fresh streaming_zip_conduit connection in {retry_delay_ms} ms"
                );
                tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
            }
            Err(error) => {
                warn!(
                    "Apple Watch install/update failed for {bundle_id} on attempt {attempt}/{WATCH_INSTALL_ATTEMPTS}; the existing Watch app was not explicitly uninstalled"
                );
                return Err(error);
            }
        }
    }

    unreachable!("bounded Watch install retry loop must return")
}

async fn install_watch_app_with_retry_rsd(
    rsd_provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    watch_lockdown: &mut LockdownClient,
    watch_pairing: &PairingFile,
    legacy: bool,
    watch_app: &Bundle,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    let bundle_id = watch_app
        .bundle_identifier()
        .ok_or_report()
        .context("Watch app is missing CFBundleIdentifier")?;

    for attempt in 1..=WATCH_INSTALL_ATTEMPTS {
        match install_watch_app_zip_conduit_rsd(
            rsd_provider,
            handshake,
            watch_lockdown,
            watch_pairing,
            legacy,
            watch_app,
            progress_callback,
        )
        .await
        {
            Ok(()) => {
                if attempt > 1 {
                    info!(
                        "Apple Watch app {bundle_id} installed/updated over RSD after {attempt} attempts"
                    );
                }
                return Ok(());
            }
            Err(error)
                if watch_retry_delay(attempt, is_watch_coordinator_conflict(&error)).is_some() =>
            {
                let retry_delay_ms = watch_retry_delay(attempt, true).unwrap().as_millis() as u64;
                warn!(
                    "Apple Watch RSD install coordinator still busy for {bundle_id} (attempt {attempt}/{WATCH_INSTALL_ATTEMPTS}); retrying with a fresh streaming_zip_conduit connection in {retry_delay_ms} ms"
                );
                tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
            }
            Err(error) => {
                warn!(
                    "Apple Watch RSD install/update failed for {bundle_id} on attempt {attempt}/{WATCH_INSTALL_ATTEMPTS}; the existing Watch app was not explicitly uninstalled"
                );
                return Err(error);
            }
        }
    }

    unreachable!("bounded Watch RSD install retry loop must return")
}

fn is_watch_coordinator_conflict(error: &Report) -> bool {
    // Rootcause context can hide the device's error in Display; inspect its chain
    // internally but NEVER write that Debug representation to a log.
    is_coordinator_message(&format!("{error:?}\n{error}"))
}

fn is_coordinator_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.split("ixerrordomain code=48").skip(1).any(|suffix| {
        !suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
    }) || message.contains("a coordinated install exists for this identity")
        || (message.contains("process-scoped") && message.contains("scoped to a different process"))
}

fn watch_retry_delay(attempt: usize, coordinator_busy: bool) -> Option<Duration> {
    if !coordinator_busy || attempt == 0 || attempt >= WATCH_INSTALL_ATTEMPTS {
        return None;
    }
    let factor = 1u64.checked_shl((attempt - 1) as u32).unwrap_or(u64::MAX);
    Some(Duration::from_millis(WATCH_INSTALL_INITIAL_RETRY_DELAY_MS
        .saturating_mul(factor).min(WATCH_INSTALL_MAX_RETRY_DELAY_MS)))
}

async fn install_watch_app_zip_conduit(
    device_provider: &impl IdeviceProvider,
    watch_lockdown: &mut LockdownClient,
    watch_pairing: &PairingFile,
    legacy: bool,
    watch_app: &Bundle,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    let (remote_port, ssl) = watch_io_for(WATCH_IO_TIMEOUT, watch_lockdown
        .start_service(WATCH_ZIP_SERVICE))
        .await
        .map_err(Error::IdeviceError)
        .context("Failed to start Apple Watch streaming_zip_conduit")?;

    let forwarded_port = start_watch_forward(device_provider, remote_port, WATCH_ZIP_SERVICE).await?;

    let result = async {
        let mut connection = connect_forwarded_watch_port(
            device_provider,
            forwarded_port,
            "streaming_zip_conduit",
        )
        .await?;

        if ssl {
            watch_io_for(WATCH_IO_TIMEOUT, connection
                .start_session(watch_pairing, legacy))
                .await
                .map_err(Error::IdeviceError)
                .context("Failed to secure Apple Watch streaming_zip_conduit connection")?;
        }

        tokio::time::timeout(WATCH_TRANSFER_TIMEOUT,
            stream_watch_app(&mut connection, watch_app, progress_callback))
            .await.map_err(|_| report!("Apple Watch signed-bundle transfer/install deadline exceeded"))?

    }
    .await;

    stop_watch_forward(device_provider, remote_port).await;

    result
}

async fn install_watch_app_zip_conduit_rsd(
    rsd_provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    watch_lockdown: &mut LockdownClient,
    watch_pairing: &PairingFile,
    legacy: bool,
    watch_app: &Bundle,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    let (remote_port, ssl) = watch_io_for(WATCH_IO_TIMEOUT, watch_lockdown
        .start_service(WATCH_ZIP_SERVICE))
        .await
        .map_err(Error::IdeviceError)
        .context("Failed to start Apple Watch streaming_zip_conduit over RSD")?;

    let forwarded_port = start_watch_forward_rsd(rsd_provider, handshake, remote_port, WATCH_ZIP_SERVICE).await?;

    let result = async {
        let mut connection = connect_forwarded_watch_port_rsd(
            rsd_provider,
            forwarded_port,
            "streaming_zip_conduit",
        )
        .await?;

        if ssl {
            watch_io_for(WATCH_IO_TIMEOUT, connection
                .start_session(watch_pairing, legacy))
                .await
                .map_err(Error::IdeviceError)
                .context("Failed to secure Apple Watch RSD streaming_zip_conduit connection")?;
        }

        tokio::time::timeout(WATCH_TRANSFER_TIMEOUT,
            stream_watch_app(&mut connection, watch_app, progress_callback))
            .await.map_err(|_| report!("Apple Watch signed-bundle transfer/install deadline exceeded"))?

    }
    .await;

    stop_watch_forward_rsd(rsd_provider, handshake, remote_port).await;

    result
}

async fn stream_watch_app(
    connection: &mut Idevice,
    watch_app: &Bundle,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    let app_name = watch_app
        .bundle_dir
        .file_name()
        .ok_or_report()
        .context("Watch app path has no file name")?
        .to_str().ok_or_report().context("Watch app name is not UTF-8")?
        .to_string();
    validate_zip_path(&format!("Payload/{app_name}/"))?;

    let mut files = Vec::new();
    collect_files(&watch_app.bundle_dir, &mut files, 0)?;
    files.sort();

    let mut entries = Vec::with_capacity(files.len());
    let mut total_uncompressed = 0u64;

    for source in files {
        let relative = source
            .strip_prefix(&watch_app.bundle_dir)
            .context("Failed to create relative Watch app path")?;
        let relative = archive_relative_path(relative)?;
        let metadata = isideload_vfs::fs::metadata(&source)?;
        let directory = metadata.is_dir();
        let destination = format!("Payload/{app_name}/{relative}{}", if directory { "/" } else { "" });
        validate_zip_path(&destination)?;
        let size = if directory { 0 } else { metadata.len() };
        u32::try_from(size).context("Watch app resource exceeds ZIP32 size limit")?;
        total_uncompressed = total_uncompressed.checked_add(size)
            .ok_or_report().context("Watch app size overflow")?;
        entries.push((source, destination, size, directory));
    }

    let media_subdir = format!("PublicStaging/{app_name}.ipa");
    let mut install_options = Dictionary::new();
    insert_integer(&mut install_options, "DisableDeltaTransfer", 1);
    insert_string(
        &mut install_options,
        "InstallDeltaTypeKey",
        "InstallDeltaTypeSparseIPAFiles",
    );
    insert_integer(&mut install_options, "IsUserInitiated", 1);
    insert_string(&mut install_options, "PackageType", "Customer");
    insert_integer(&mut install_options, "PreferWifi", 1);

    let mut init_transfer = Dictionary::new();
    init_transfer.insert(
        "InstallOptionsDictionary".to_string(),
        Value::Dictionary(install_options),
    );
    insert_integer(&mut init_transfer, "InstallTransferredDirectory", 1);
    insert_string(&mut init_transfer, "MediaSubdir", media_subdir);
    insert_integer(&mut init_transfer, "UserInitiatedTransfer", 0);

    send_prefixed_plist(connection, init_transfer).await?;

    let mut metadata = Dictionary::new();
    insert_integer(&mut metadata, "StandardDirectoryPerms", 16877);
    insert_integer(&mut metadata, "StandardFilePerms", -32348);
    insert_integer(
        &mut metadata,
        "RecordCount",
        i64::try_from(entries.len() + 2).context("Too many Watch app files")?,
    );
    insert_integer(
        &mut metadata,
        "TotalUncompressedBytes",
        i64::try_from(total_uncompressed).context("Watch app is too large")?,
    );
    insert_integer(&mut metadata, "Version", 2);

    let mut metadata_bytes = Vec::new();
    Value::Dictionary(metadata).to_writer_xml(&mut metadata_bytes)?;

    send_zip_directory(connection, "META-INF/").await?;
    send_zip_file(
        connection,
        "META-INF/com.apple.ZipMetadata.plist",
        &metadata_bytes,
    )
    .await?;

    // Include ALL signed resources: _CodeSignature, embedded.mobileprovision,
    // frameworks, Watch extensions and any other nested bundle files.
    for (source, destination, size, directory) in entries {
        if directory {
            send_zip_directory(connection, &destination).await?;
        } else {
            let data = isideload_vfs::fs::read(&source)?;
            if data.len() as u64 != size {
                bail!("Watch resource changed during transfer");
            }
            send_zip_file(connection, &destination, &data).await?;
        }
    }

    watch_io_for(WATCH_IO_TIMEOUT, connection
        .send_raw(CENTRAL_DIRECTORY_HEADER))
        .await
        .map_err(Error::IdeviceError)?;

    tokio::time::timeout(WATCH_INSTALL_TIMEOUT,
        wait_for_watch_install(connection, progress_callback))
        .await.map_err(|_| report!("Apple Watch installation status deadline exceeded"))?

}

#[derive(Debug, PartialEq, Eq)]
enum InstallResponse {
    Complete,
    Progress(u64),
}

// Inspect errors BEFORE completion: an error-bearing DataComplete is not success.
fn parse_install_response(response: &Dictionary) -> Result<InstallResponse, Report> {
    check_install_error(response)?;
    let progress = response.get("InstallProgressDict").and_then(Value::as_dictionary);
    if let Some(progress) = progress {
        check_install_error(progress)?;
    }
    if response.get("Status").and_then(Value::as_string) == Some("DataComplete") {
        return Ok(InstallResponse::Complete);
    }
    let progress = progress.ok_or_report().context("Unexpected Apple Watch install response")?;
    let percent = progress.get("PercentComplete").and_then(Value::as_unsigned_integer).unwrap_or(0);
    // Only DataComplete is authoritative completion, even if progress reports 100.
    Ok(InstallResponse::Progress(percent.min(99)))
}

fn check_install_error(dictionary: &Dictionary) -> Result<(), Report> {
    if let Some(error) = dictionary.get("Error") {
        // Some builds include an empty/zero error field in normal progress.
        if error.as_string() == Some("") || error.as_unsigned_integer() == Some(0) {
            return Ok(());
        }
        let error = error.as_string().unwrap_or("Non-string watchOS installation error");
        let description = dictionary.get("ErrorDescription").and_then(Value::as_string)
            .unwrap_or("No ErrorDescription returned by watchOS");
        bail!("Apple Watch installation failed: {error}: {description}");
    }
    Ok(())
}

async fn wait_for_watch_install(
    connection: &mut Idevice,
    progress_callback: &(impl Fn(u64) + Send + Sync),
) -> Result<(), Report> {
    loop {
        match parse_install_response(&read_prefixed_plist(connection).await?)? {
            InstallResponse::Complete => {
                progress_callback(100);
                info!("Apple Watch installation completed");
                return Ok(());
            }
            InstallResponse::Progress(percent) => progress_callback(percent),
        }
    }
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>, depth: usize) -> Result<(), Report> {
    if depth >= MAX_BUNDLE_DEPTH {
        bail!("Watch bundle nesting limit exceeded (possible directory cycle)");
    }
    for entry in isideload_vfs::fs::read_dir(dir)? {
        let path = entry?.path();
        let metadata = isideload_vfs::fs::metadata(&path)?;
        if metadata.is_dir() {
            files.push(path.clone()); // Includes empty directories; never filter signed resources.
            collect_files(&path, files, depth + 1)?;
        } else if metadata.is_file() {
            files.push(path);
        } else {
            bail!("Unsupported filesystem entry in signed Watch bundle");
        }
    }
    Ok(())
}

fn archive_relative_path(path: &Path) -> Result<String, Report> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(name) => parts.push(name.to_str().ok_or_report()
                .context("Watch resource path is not UTF-8")?),
            _ => bail!("Watch resource path is not relative"),
        }
    }
    let path = parts.join("/");
    validate_zip_path(&path)?;
    Ok(path)
}

fn validate_zip_path(name: &str) -> Result<(), Report> {
    let path = name.strip_suffix('/').unwrap_or(name);
    if path.is_empty() || path.chars().any(|ch| matches!(ch, '\\' | '\0' | ':'))
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        bail!("Invalid path in signed Watch bundle");
    }
    u16::try_from(name.len()).context("Watch zip path is too long")?;
    Ok(())
}

fn encode_plist_frame(dictionary: Dictionary) -> Result<Vec<u8>, Report> {
    let mut payload = Vec::new();
    Value::Dictionary(dictionary).to_writer_xml(&mut payload)?;
    if payload.len() > MAX_PLIST_BYTES {
        bail!("Watch plist exceeds frame size limit");
    }
    let payload_len = u32::try_from(payload.len()).context("Watch plist is too large")?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn parse_plist_length(prefix: &[u8]) -> Result<usize, Report> {
    let prefix: [u8; 4] = prefix.try_into().context("Truncated Watch plist length prefix")?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_PLIST_BYTES {
        bail!("Invalid Apple Watch plist frame length");
    }
    Ok(length)
}

fn decode_plist_payload(payload: &[u8]) -> Result<Dictionary, Report> {
    match plist::from_bytes::<Value>(payload)? {
        Value::Dictionary(dictionary) => Ok(dictionary),
        _ => bail!("Expected dictionary plist from Apple Watch"),
    }
}

async fn send_prefixed_plist(connection: &mut Idevice, dictionary: Dictionary) -> Result<(), Report> {
    let frame = encode_plist_frame(dictionary)?;
    watch_io_for(WATCH_IO_TIMEOUT, connection.send_raw(&frame)).await.map_err(Error::IdeviceError)?;
    Ok(())
}

async fn read_prefixed_plist(connection: &mut Idevice) -> Result<Dictionary, Report> {
    let prefix = watch_io_for(WATCH_IO_TIMEOUT, connection.read_raw(4)).await.map_err(Error::IdeviceError)?;
    let length = parse_plist_length(&prefix)?;
    let payload = watch_io_for(WATCH_IO_TIMEOUT, connection.read_raw(length)).await.map_err(Error::IdeviceError)?;
    decode_plist_payload(&payload)
}

async fn send_zip_directory(connection: &mut Idevice, name: &str) -> Result<(), Report> {
    let header = zip_header(name, 0, 0)?;
    watch_io_for(WATCH_IO_TIMEOUT, connection
        .send_raw(&header))
        .await
        .map_err(Error::IdeviceError)?;
    Ok(())
}

async fn send_zip_file(connection: &mut Idevice, name: &str, data: &[u8]) -> Result<(), Report> {
    let size = u32::try_from(data.len()).context("Watch app file is too large")?;
    let header = zip_header(name, size, crc32_ieee(data))?;

    watch_io_for(WATCH_IO_TIMEOUT, connection
        .send_raw(&header))
        .await
        .map_err(Error::IdeviceError)?;
    if !data.is_empty() {
        watch_io_for(WATCH_IO_TIMEOUT, connection.send_raw(data))
            .await.map_err(Error::IdeviceError)?;
    }
    Ok(())
}

fn zip_header(name: &str, size: u32, crc32: u32) -> Result<Vec<u8>, Report> {
    validate_zip_path(name)?;
    let name_bytes = name.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).context("Watch zip path is too long")?;
    let extra_len = u16::try_from(ZIP_EXTRA.len()).context("Watch zip extra data is too large")?;

    let mut header = Vec::with_capacity(30 + name_bytes.len() + ZIP_EXTRA.len());
    push_u32_le(&mut header, 0x04034b50);
    push_u16_le(&mut header, 20);
    push_u16_le(&mut header, 0x0800); // UTF-8 path names, stored/uncompressed data.
    push_u16_le(&mut header, 0);
    push_u16_le(&mut header, 0xbdef);
    push_u16_le(&mut header, 0x52ec);
    push_u32_le(&mut header, crc32);
    push_u32_le(&mut header, size);
    push_u32_le(&mut header, size);
    push_u16_le(&mut header, name_len);
    push_u16_le(&mut header, extra_len);
    header.extend_from_slice(name_bytes);
    header.extend_from_slice(ZIP_EXTRA);
    Ok(header)
}

fn push_u16_le(buffer: &mut Vec<u8>, value: u16) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

fn insert_string(dictionary: &mut Dictionary, key: &str, value: impl Into<String>) {
    dictionary.insert(key.to_string(), Value::String(value.into()));
}

fn insert_integer(dictionary: &mut Dictionary, key: &str, value: i64) {
    dictionary.insert(key.to_string(), Value::Integer(value.into()));
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;

    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }

    !crc
}

// Raw network calls are individually bounded; transfer/install also have overall deadlines.
async fn watch_io_for<T>(
    timeout: Duration,
    future: impl Future<Output = Result<T, idevice::IdeviceError>>,
) -> Result<T, idevice::IdeviceError> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        idevice::IdeviceError::UnexpectedResponse("Apple Watch operation timed out".into())
    })?
}

async fn start_watch_forward(
    provider: &impl IdeviceProvider,
    remote_port: u16,
    service: &str,
) -> Result<u16, Report> {
    let mut proxy = watch_io_for(WATCH_IO_TIMEOUT, CompanionProxy::connect(provider))
        .await.map_err(Error::IdeviceError).context("Failed to connect to Watch companion proxy")?;
    let result = watch_io_for(WATCH_IO_TIMEOUT,
        proxy.start_forwarding_service_port(remote_port, Some(service), None)).await;
    drop(proxy); // A fresh proxy is required for the next command/cleanup on some iOS builds.
    if result.is_err() {
        // The command might have succeeded device-side before its reply was lost.
        stop_watch_forward(provider, remote_port).await;
    }
    result.map_err(Error::IdeviceError).context("Failed to start Watch service forwarding")
}

async fn stop_watch_forward(provider: &impl IdeviceProvider, remote_port: u16) {
    let result = async {
        let mut proxy = watch_io_for(WATCH_IO_TIMEOUT, CompanionProxy::connect(provider)).await?;
        watch_io_for(WATCH_IO_TIMEOUT, proxy.stop_forwarding_service_port(remote_port)).await
    }.await;
    if result.is_err() {
        // Do not dump opaque error reports: provider/pairing Debug can contain private material.
        warn!(remote_port, "Could not stop Watch forwarding; transport may already be disconnected");
    }
}

async fn start_watch_forward_rsd(
    provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    remote_port: u16,
    service: &str,
) -> Result<u16, Report> {
    let mut proxy = watch_io_for(WATCH_IO_TIMEOUT, CompanionProxy::connect_rsd(provider, handshake))
        .await.map_err(Error::IdeviceError).context("Failed to connect to Watch RSD companion proxy")?;
    let result = watch_io_for(WATCH_IO_TIMEOUT,
        proxy.start_forwarding_service_port(remote_port, Some(service), None)).await;
    drop(proxy);
    if result.is_err() {
        stop_watch_forward_rsd(provider, handshake, remote_port).await;
    }
    result.map_err(Error::IdeviceError).context("Failed to start Watch RSD service forwarding")
}

async fn stop_watch_forward_rsd(
    provider: &mut impl RsdProvider,
    handshake: &mut RsdHandshake,
    remote_port: u16,
) {
    let result = async {
        let mut proxy = watch_io_for(WATCH_IO_TIMEOUT, CompanionProxy::connect_rsd(provider, handshake)).await?;
        watch_io_for(WATCH_IO_TIMEOUT, proxy.stop_forwarding_service_port(remote_port)).await
    }.await;
    if result.is_err() {
        warn!(remote_port, "Could not stop Watch RSD forwarding; transport may already be disconnected");
    }
}

#[cfg(test)]
#[path = "watch_install_tests.rs"]
mod tests;
