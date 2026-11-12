//! Privacy-safe stage diagnostics for forwarded Watch lockdown, not a new pairing protocol.
//! idevice still generates and submits its own pairing request/certificates. We do
//! not reuse a phone record as a Watch record, skip trust, or write pairing data.
use std::{future::Future, time::Duration};
use idevice::{Idevice, IdeviceError, pairing_file::PairingFile, services::lockdown::LockdownClient};
use rootcause::prelude::*;
use tracing::{info, warn};

const IO_LIMIT: Duration = Duration::from_secs(15);
const PAIR_LIMIT: Duration = Duration::from_secs(90);
const EXPECTED_LOCKDOWN_TYPE: &str = "com.apple.mobile.lockdown";

async fn stage<T>(
    transport: &'static str,
    phase: &'static str,
    limit: Duration,
    operation: impl Future<Output = Result<T, IdeviceError>>,
) -> Result<T, Report> {
    info!(target: "iloader_watch::diagnostic", stage = phase, transport, timeout_seconds = limit.as_secs(), "Watch stage started");
    match tokio::time::timeout(limit, operation).await {
        Ok(Ok(value)) => {
            info!(target: "iloader_watch::diagnostic", stage = phase, transport, "Watch stage completed");
            Ok(value)
        }
        Ok(Err(error)) => {
            let code = error.code();
            warn!(target: "iloader_watch::diagnostic", stage = phase, transport, device_error_code = code, "Watch stage returned a device error; no private payload logged");
            bail!("[WatchStage:{}] {} returned device error code {}. No successful Watch installation was reported; pairing/private payloads were not logged", phase, transport, code);
        }
        Err(_) => {
            warn!(target: "iloader_watch::diagnostic", stage = phase, transport, "Watch stage deadline exceeded");
            bail!("[WatchStage:{}] {} timed out after {} seconds. This identifies a protocol phase, not an Apple account/signing rejection. Keep the Watch unlocked and do not reset its app data or certificates", phase, transport, limit.as_secs());
        }
    }
}

fn validate_lockdown_type(kind: &str) -> Result<(), Report> {
    if kind != EXPECTED_LOCKDOWN_TYPE {
        // Do not echo an arbitrary response body/type from an unverified peer.
        bail!("[WatchStage:lockdown_query_type] Forwarded endpoint did not identify itself as lockdown; no pairing credentials were submitted");
    }
    Ok(())
}

/// Probe the target before Pair so an open but silent/wrong forwarded socket
/// cannot be misreported as a 90-second trust prompt. Read-only preflights are
/// repeated internally by idevice::pair; no custom certificates are generated here.
pub(super) async fn authenticate(
    mut connection: Idevice,
    iphone_pairing: &PairingFile,
    host_name: &str,
    transport: &'static str,
) -> Result<(LockdownClient, PairingFile, bool, String), Report> {
    let kind = stage(transport, "lockdown_query_type", IO_LIMIT, connection.get_type()).await?;
    validate_lockdown_type(&kind)?;
    let mut lockdown = LockdownClient::new(connection);
    let public_key = stage(transport, "device_public_key", IO_LIMIT,
        lockdown.get_value(Some("DevicePublicKey"), None)).await?;
    if !public_key.as_data().is_some_and(|bytes| !bytes.is_empty()) {
        bail!("[WatchStage:device_public_key] Watch did not provide a usable public key; no pairing attempt was made");
    }
    drop(public_key);
    let wifi = stage(transport, "wifi_address", IO_LIMIT,
        lockdown.get_value(Some("WiFiAddress"), None)).await?;
    if !wifi.as_string().is_some_and(|value| !value.trim().is_empty()) {
        bail!("[WatchStage:wifi_address] Watch did not provide the pairing metadata required by the device library");
    }
    drop(wifi);
    // The existing library's pair() performs its own key/metadata reads,
    // certificate generation and pending-trust loop. A timeout here alone cannot
    // distinguish those internals. Never claim the user denied trust on this basis.
    info!(target: "iloader_watch::diagnostic", stage = "pair_build_or_trust", transport, "Preparing Watch pairing; check the unlocked Watch/iPhone for any trust request");
    let pair = stage(transport, "pair_build_or_trust", PAIR_LIMIT,
        lockdown.pair(iphone_pairing.host_id.clone(), iphone_pairing.system_buid.clone(), Some(host_name))).await?;
    let legacy = stage(transport, "watch_session", IO_LIMIT, lockdown.start_session(&pair)).await?;
    let identity = stage(transport, "authenticated_watch_identity", IO_LIMIT,
        lockdown.get_value(Some("UniqueDeviceID"), None)).await?;
    let udid = identity.as_string().filter(|id| !id.trim().is_empty())
        .ok_or_else(|| report!("Authenticated Watch did not provide an identity for profile authorization"))?
        .to_string();
    Ok((lockdown, pair, legacy, udid))
}

#[cfg(test)]
#[path = "watch_pairing_tests.rs"]
mod tests;
