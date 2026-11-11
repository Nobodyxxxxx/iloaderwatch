use std::sync::atomic::{AtomicBool, Ordering};

use isideload::util::{keyring_storage::KeyringStorage, storage::SideloadingStorage};
use tauri::AppHandle;
use tracing::warn;

use crate::error::AppError;

static FORCE_DISABLE_KEYRING: AtomicBool = AtomicBool::new(false);
pub(crate) const KEYRING_SERVICE: &str = "io.github.nobodyxxxxx.iloaderwatch";

#[tauri::command]
pub fn force_disable_keyring(force: bool) {
    FORCE_DISABLE_KEYRING.store(force, Ordering::Relaxed);

    if force {
        warn!("Keyring has been forcefully disabled by the user.");
    } else {
        let available = check_keyring_available();
        if !available {
            warn!("Keyring is not available and cannot be enabled.");
        }
    }
}

#[tauri::command]
pub fn keyring_available() -> bool {
    !FORCE_DISABLE_KEYRING.load(Ordering::Relaxed) && check_keyring_available()
}

fn check_keyring_available() -> bool {
    let entry = keyring::Entry::new(KEYRING_SERVICE, "test");
    if let Ok(entry) = entry {
        return entry.set_password("test").is_ok() && entry.get_password().is_ok();
    }
    false
}

pub fn create_sideloading_storage(
    _app: &AppHandle,
) -> Result<Box<dyn SideloadingStorage>, AppError> {
    if !keyring_available() {
        return Err(AppError::Misc(
            "Secure credential storage is unavailable. This experimental build refuses to save signing or pairing secrets in unencrypted files. Re-enable the Windows credential manager instead of disabling keyring.".into(),
        ));
    }
    Ok(Box::new(KeyringStorage::new(KEYRING_SERVICE.to_string())))
}
