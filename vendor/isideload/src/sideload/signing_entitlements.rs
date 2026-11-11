//! Original entitlement extraction for companion signing. No device or portal required.
//! Fail closed on malformed/DER-only signatures rather than silently dropping permissions.
use plist::{Dictionary, Value};
use rootcause::prelude::*;

fn bytes(data: &[u8], at: usize, len: usize) -> Result<&[u8], Report> {
    let end = at.checked_add(len).ok_or_else(|| report!("Mach-O offset overflow"))?;
    data.get(at..end).ok_or_else(|| report!("Truncated Mach-O/signature"))
}
fn u32_at(data: &[u8], at: usize, le: bool) -> Result<u32, Report> {
    let v: [u8; 4] = bytes(data, at, 4)?.try_into()?;
    Ok(if le { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) })
}
fn u64_at(data: &[u8], at: usize, le: bool) -> Result<u64, Report> {
    let v: [u8; 8] = bytes(data, at, 8)?.try_into()?;
    Ok(if le { u64::from_le_bytes(v) } else { u64::from_be_bytes(v) })
}

pub(super) fn extract(data: &[u8]) -> Result<Dictionary, Report> {
    extract_inner(data, 0)
}
fn extract_inner(data: &[u8], depth: usize) -> Result<Dictionary, Report> {
    if depth > 4 { bail!("Excessively nested universal Mach-O"); }
    let magic = u32_at(data, 0, false)?;
    if matches!(magic, 0xcafebabe | 0xbebafeca | 0xcafebabf | 0xbfbafeca) {
        let le = matches!(magic, 0xbebafeca | 0xbfbafeca);
        let wide = matches!(magic, 0xcafebabf | 0xbfbafeca);
        let count = u32_at(data, 4, le)? as usize;
        let stride = if wide { 32 } else { 20 };
        if count == 0 || count > data.len().saturating_sub(8) / stride { bail!("Invalid universal Mach-O table"); }
        let mut result: Option<Dictionary> = None;
        for i in 0..count {
            let at = 8 + i * stride;
            let (offset, size) = if wide {
                (u64_at(data, at + 8, le)?, u64_at(data, at + 16, le)?)
            } else {
                (u32_at(data, at + 8, le)? as u64, u32_at(data, at + 12, le)? as u64)
            };
            let entitlements = extract_inner(bytes(data, usize::try_from(offset)?, usize::try_from(size)?)?, depth + 1)?;
            if result.as_ref().is_some_and(|previous| previous != &entitlements) {
                bail!("Universal Mach-O slices require different entitlements");
            }
            result = Some(entitlements);
        }
        return Ok(result.unwrap_or_default());
    }
    let (le, header) = match magic {
        0xcefaedfe => (true, 28), 0xcffaedfe => (true, 32),
        0xfeedface => (false, 28), 0xfeedfacf => (false, 32),
        _ => bail!("Executable is not Mach-O"),
    };
    let count = u32_at(data, 16, le)? as usize;
    let commands_len = u32_at(data, 20, le)? as usize;
    let commands = bytes(data, header, commands_len)?;
    if count > commands.len() / 8 { bail!("Invalid Mach-O command count"); }
    let mut at = 0;
    for _ in 0..count {
        let command = u32_at(commands, at, le)?;
        let size = u32_at(commands, at + 4, le)? as usize;
        if size < 8 { bail!("Invalid Mach-O load command size"); }
        let cmd = bytes(commands, at, size)?;
        if command == 0x1d {
            let offset = u32_at(cmd, 8, le)? as usize;
            let len = u32_at(cmd, 12, le)? as usize;
            if len == 0 { return Ok(Dictionary::new()); }
            return signature_entitlements(bytes(data, offset, len)?);
        }
        at += size;
    }
    Ok(Dictionary::new()) // unsigned Mach-O, no permissions to lose
}

fn signature_entitlements(data: &[u8]) -> Result<Dictionary, Report> {
    if u32_at(data, 0, false)? != 0xfade0cc0 { bail!("Invalid embedded signature superblob"); }
    let length = u32_at(data, 4, false)? as usize;
    let data = bytes(data, 0, length)?;
    let count = u32_at(data, 8, false)? as usize;
    if count > data.len().saturating_sub(12) / 8 { bail!("Invalid signature blob index"); }
    let mut xml = None;
    let mut der = false;
    for i in 0..count {
        let slot = u32_at(data, 12 + i * 8, false)?;
        let offset = u32_at(data, 16 + i * 8, false)? as usize;
        let magic = u32_at(data, offset, false)?;
        let len = u32_at(data, offset + 4, false)? as usize;
        if len < 8 { bail!("Invalid entitlement blob length"); }
        let blob = bytes(data, offset, len)?;
        if slot == 5 && magic != 0xfade7171 { bail!("Malformed XML entitlement signature slot"); }
        if slot == 5 && magic == 0xfade7171 {
            let payload = &blob[8..];
            let end = payload.iter().rposition(|byte| *byte != 0).map_or(0, |at| at + 1);
            let value: Value = plist::from_bytes(&payload[..end])?;
            xml = Some(value.into_dictionary().ok_or_else(|| report!("Entitlements are not a dictionary"))?);
        }
        if slot == 7 || magic == 0xfade7172 { der = true; }
    }
    match xml {
        Some(value) => Ok(value),
        None if der => bail!("DER-only entitlements cannot be preserved; provide an IPA with XML entitlements"),
        None => Ok(Dictionary::new()),
    }
}

fn permits(allowed: &Value, wanted: &Value) -> bool {
    match (allowed, wanted) {
        (Value::String(a), Value::String(w)) => a == w || a.strip_suffix('*').is_some_and(|prefix| w.starts_with(prefix)),
        (Value::Array(a), Value::Array(w)) => w.iter().all(|v| a.iter().any(|a| permits(a, v))),
        (Value::Dictionary(a), Value::Dictionary(w)) => w.iter().all(|(k,v)| a.get(k).is_some_and(|a| permits(a,v))),
        _ => allowed == wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_macho(entitlements: &Dictionary) -> Vec<u8> {
        let mut xml = Vec::new();
        plist::to_writer_xml(&mut xml, entitlements).unwrap();
        let mut blob = Vec::new();
        for n in [0xfade0cc0u32, (28 + xml.len()) as u32, 1, 5, 20, 0xfade7171, (8 + xml.len()) as u32] {
            blob.extend_from_slice(&n.to_be_bytes());
        }
        blob.extend_from_slice(&xml);
        let mut macho = vec![0u8; 48];
        macho[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        macho[16..20].copy_from_slice(&1u32.to_le_bytes());
        macho[20..24].copy_from_slice(&16u32.to_le_bytes());
        for (at, n) in [(32, 0x1du32), (36, 16), (40, 48), (44, blob.len() as u32)] {
            macho[at..at + 4].copy_from_slice(&n.to_le_bytes());
        }
        macho.extend_from_slice(&blob);
        macho
    }

    #[test]
    fn extracts_original_groups_from_watch_executable() {
        let mut original = Dictionary::new();
        original.insert("com.apple.security.application-groups".into(), Value::Array(vec!["group.shared".into()]));
        assert_eq!(extract(&signed_macho(&original)).unwrap(), original);
    }

    #[test]
    fn rejects_truncated_or_overflowing_signature() {
        let mut data = signed_macho(&Dictionary::new());
        data[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(extract(&data).is_err());
        assert!(extract(&[0, 1, 2]).is_err());
    }

    #[test]
    fn extracts_fat_slices_and_rejects_inconsistent_permissions() {
        let first = signed_macho(&Dictionary::new());
        let mut requested = Dictionary::new();
        requested.insert("com.apple.developer.healthkit".into(), Value::Boolean(true));
        let second = signed_macho(&requested);
        let mut fat = vec![0u8; 48];
        fat[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&2u32.to_be_bytes());
        for (at, n) in [(16, 48u32), (20, first.len() as u32), (36, (48 + first.len()) as u32), (40, second.len() as u32)] {
            fat[at..at + 4].copy_from_slice(&n.to_be_bytes());
        }
        fat.extend_from_slice(&first);
        fat.extend_from_slice(&second);
        assert!(extract(&fat).is_err());
    }

    #[test]
    fn refuses_to_drop_missing_watch_groups_or_permissions() {
        let mut required = Dictionary::new();
        required.insert("com.apple.security.application-groups".into(), Value::Array(vec!["group.required.TEAM".into()]));
        assert!(merge(&Dictionary::new(), &required, "com.watch").is_err());
        let mut profile = required.clone();
        required.insert("com.apple.developer.healthkit".into(), Value::Boolean(true));
        assert!(merge(&profile, &required, "com.watch.ext").is_err());
        profile.insert("com.apple.developer.healthkit".into(), Value::Boolean(true));
        assert_eq!(merge(&profile, &required, "com.watch.ext").unwrap(), required);
    }

    #[test]
    fn explicit_watch_profile_cannot_be_the_phone_profile() {
        let mut entitlements = Dictionary::new();
        entitlements.insert("application-identifier".into(), "TEAM.com.phone".into());
        let mut profile = Dictionary::new();
        profile.insert("Entitlements".into(), Value::Dictionary(entitlements.clone()));
        profile.insert("Platform".into(), Value::Array(vec!["iOS".into()]));
        assert!(validate_watch_profile(&profile, "com.phone.watch").is_err());
        entitlements.insert("application-identifier".into(), "TEAM.com.phone.watch".into());
        profile.insert("Entitlements".into(), Value::Dictionary(entitlements));
        assert!(validate_watch_profile(&profile, "com.phone.watch").is_err());
        profile.insert("Platform".into(), Value::Array(vec!["watchOS".into()]));
        assert!(validate_watch_profile(&profile, "com.phone.watch").is_ok());
    }

    #[test]
    fn refuses_der_only_instead_of_silently_dropping_entitlements() {
        let mut data = signed_macho(&Dictionary::new());
        data[60..64].copy_from_slice(&7u32.to_be_bytes());
        data[68..72].copy_from_slice(&0xfade7172u32.to_be_bytes());
        assert!(extract(&data).is_err());
    }

    #[test]
    fn concretizes_authorized_keychain_wildcard_without_losing_groups() {
        let mut profile = Dictionary::new();
        profile.insert("keychain-access-groups".into(), Value::Array(vec!["TEAM.*".into()]));
        let mut required = Dictionary::new();
        required.insert("keychain-access-groups".into(), Value::Array(vec!["TEAM.com.watch.shared".into()]));
        assert_eq!(merge(&profile, &required, "com.watch").unwrap(), required);
    }
}

pub(super) fn merge(profile: &Dictionary, required: &Dictionary, bundle_id: &str) -> Result<Dictionary, Report> {
    let mut merged = profile.clone();
    for (key, wanted) in required {
        // These are identities, not permissions. The destination profile supplies the new identity.
        if matches!(key.as_str(), "application-identifier" | "com.apple.application-identifier" | "com.apple.developer.team-identifier" | "get-task-allow" | "beta-reports-active") { continue; }
        if !profile.get(key).is_some_and(|allowed| permits(allowed, wanted)) {
            bail!("Provisioning profile for {} does not authorize required entitlement {}. Enable that capability/app group for this team; no permissions were stripped.", bundle_id, key);
        }
        if key == "com.apple.security.application-groups" {
            // Keep the generated 0.5.2/SpecialApp group too; ALTAppGroups refers to it.
            let mut groups = wanted.as_array().ok_or_else(|| report!("Invalid required application groups"))?.clone();
            if let Some(allowed) = profile.get(key).and_then(Value::as_array) {
                for group in allowed {
                    if group.as_string().is_some_and(|group| !group.contains('*')) && !groups.contains(group) {
                        groups.push(group.clone());
                    }
                }
            }
            merged.insert(key.clone(), Value::Array(groups));
        } else {
            merged.insert(key.clone(), wanted.clone());
        }
    }
    Ok(merged)
}

/// Profiles fetched from watchOS endpoints must belong to this explicit Watch app ID.
pub(super) fn validate_watch_profile(profile: &Dictionary, bundle_id: &str) -> Result<(), Report> {
    let id = profile.get("Entitlements").and_then(Value::as_dictionary)
        .and_then(|entitlements| entitlements.get("application-identifier"))
        .and_then(Value::as_string)
        .ok_or_else(|| report!("Watch profile for {} lacks application-identifier", bundle_id))?;
    if !id.ends_with(&format!(".{}", bundle_id)) {
        bail!("Watch profile for {} has a different application-identifier {}; refusing phone-profile reuse", bundle_id, id);
    }
    if let Some(platforms) = profile.get("Platform") {
        if !platforms.as_array().is_some_and(|platforms| platforms.iter().any(|platform|
            platform.as_string().is_some_and(|platform| platform.eq_ignore_ascii_case("watchos")))) {
            bail!("Provisioning profile for {} is not a watchOS profile", bundle_id);
        }
    }
    Ok(())
}
