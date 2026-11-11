// This file was made using https://github.com/Dadoum/Sideloader as a reference.
// I'm planning on redoing this later to better handle entitlements, extensions, etc, but it will do for now

use isideload_vfs::fs::File;
use plist::{Dictionary, Value, to_writer_binary};
use rootcause::prelude::*;
use std::{
    io::BufWriter,
    path::{Path, PathBuf},
};

use crate::SideloadError;

#[derive(Debug, Clone)]
pub struct Bundle {
    pub app_info: Dictionary,
    pub bundle_dir: PathBuf,

    app_extensions: Vec<Bundle>,
    frameworks: Vec<Bundle>,
    watch_apps: Vec<Bundle>,
    _libraries: Vec<String>,
}

impl Bundle {
    pub fn new(bundle_dir: PathBuf) -> Result<Self, Report> {
        let mut bundle_path = bundle_dir;
        // Remove trailing slash/backslash
        if let Some(path_str) = bundle_path.to_str()
            && (path_str.ends_with('/') || path_str.ends_with('\\'))
        {
            bundle_path = PathBuf::from(&path_str[..path_str.len() - 1]);
        }

        let info_plist_path = bundle_path.join("Info.plist");
        assert_bundle(
            isideload_vfs::fs::metadata(&info_plist_path).is_ok(),
            &format!("No Info.plist here: {}", info_plist_path.display()),
        )?;

        let plist_data = isideload_vfs::fs::read(&info_plist_path).context(
            SideloadError::InvalidBundle("Failed to read Info.plist".to_string()),
        )?;

        let app_info = plist::from_bytes(&plist_data).context(SideloadError::InvalidBundle(
            "Failed to parse Info.plist".to_string(),
        ))?;

        // Each child is parsed recursively, including Watch apps' own PlugIns/Frameworks/Watch.
        // Never silently discard an invalid executable bundle: it would remain unsigned.
        let app_extensions = load_child_bundles(&bundle_path.join("PlugIns"), false)?;
        let frameworks = load_child_bundles(&bundle_path.join("Frameworks"), false)?;
        let watch_apps = load_child_bundles(&bundle_path.join("Watch"), true)?;

        // Find all .dylib files in the bundle directory (recursive)
        let libraries = find_dylibs(&bundle_path, &bundle_path)?;

        Ok(Bundle {
            app_info,
            bundle_dir: bundle_path,
            app_extensions,
            frameworks,
            watch_apps,
            _libraries: libraries,
        })
    }

    pub fn set_bundle_identifier(&mut self, id: &str) {
        let old_id = self.bundle_identifier().and_then(|s| Some(s.to_string()));
        if let Some(Value::Array(bg_tasks)) =
            self.app_info.get_mut("BGTaskSchedulerPermittedIdentifiers")
        {
            for task in bg_tasks.iter_mut() {
                if let Value::String(task_id) = task {
                    if let Some(old_bundle_id) = &old_id {
                        if task_id.contains(old_bundle_id) {
                            *task_id = task_id.replace(old_bundle_id, id);
                        }
                    }
                }
            }
        }

        self.app_info.insert(
            "CFBundleIdentifier".to_string(),
            Value::String(id.to_string()),
        );
    }

    pub fn bundle_identifier(&self) -> Option<&str> {
        self.app_info
            .get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
    }

    pub fn bundle_name(&self) -> Option<&str> {
        self.app_info
            .get("CFBundleName")
            .and_then(|v| v.as_string())
    }

    pub fn app_extensions(&self) -> &[Bundle] {
        &self.app_extensions
    }

    pub fn app_extensions_mut(&mut self) -> &mut [Bundle] {
        &mut self.app_extensions
    }

    pub fn frameworks(&self) -> &[Bundle] {
        &self.frameworks
    }

    pub fn frameworks_mut(&mut self) -> &mut [Bundle] {
        &mut self.frameworks
    }

    pub fn watch_apps(&self) -> &[Bundle] {
        &self.watch_apps
    }

    pub fn watch_apps_mut(&mut self) -> &mut [Bundle] {
        &mut self.watch_apps
    }

    /// Executable app/extension bundles requiring profiles (not frameworks or dylibs).
    pub fn collect_app_id_bundles(&self) -> Vec<&Bundle> {
        let mut bundles = vec![self];
        for child in self.app_extensions.iter().chain(self.watch_apps.iter()) {
            bundles.extend(child.collect_app_id_bundles());
        }
        bundles
    }

    /// Rewrite only identifiers owned by this companion tree; vendor frameworks keep theirs.
    pub fn rewrite_embedded_bundle_ids(&mut self, old: &str, new: &str) -> Result<(), Report> {
        for child in self.app_extensions.iter_mut().chain(self.watch_apps.iter_mut()) {
            let id = child.bundle_identifier()
                .ok_or_else(|| report!("Missing child CFBundleIdentifier"))?.to_string();
            if !id.strip_prefix(old).is_some_and(|suffix| suffix.starts_with('.')) {
                bail!(SideloadError::InvalidBundle(format!(
                    "Child bundle identifier {} is not a descendant of {}", id, old
                )));
            }
            child.set_bundle_identifier(&format!("{}{}", new, &id[old.len()..]));
            child.rewrite_embedded_bundle_ids(old, new)?;
        }
        rewrite_watch_references(&mut self.app_info, old, new);
        Ok(())
    }

    pub(crate) fn validate_watch_links(&self, companion: &str, watches: &std::collections::HashSet<String>) -> Result<(), Report> {
        fn validate(info: &Dictionary, companion: &str, watches: &std::collections::HashSet<String>) -> Result<(), Report> {
            for (key, value) in info {
                if matches!(key.as_str(), "WKCompanionAppBundleIdentifier" | "WKAppBundleIdentifier") {
                    let id = value.as_string().ok_or_else(|| report!("Invalid Watch bundle reference {}", key))?;
                    if (key == "WKCompanionAppBundleIdentifier" && id != companion)
                        || (key == "WKAppBundleIdentifier" && !watches.contains(id)) {
                        bail!("Invalid {} reference {} in companion tree", key, id);
                    }
                }
                if let Value::Dictionary(dict) = value { validate(dict, companion, watches)?; }
            }
            Ok(())
        }
        validate(&self.app_info, companion, watches)?;
        for child in self.app_extensions.iter().chain(self.watch_apps.iter()) {
            child.validate_watch_links(companion, watches)?;
        }
        Ok(())
    }

    pub fn write_info_recursive(&self) -> Result<(), Report> {
        self.write_info()?;
        for child in self.app_extensions.iter().chain(self.frameworks.iter()).chain(self.watch_apps.iter()) {
            child.write_info_recursive()?;
        }
        Ok(())
    }

    pub fn write_info(&self) -> Result<(), Report> {
        let info_plist_path = self.bundle_dir.join("Info.plist");
        // plist::to_file_binary(&info_plist_path, &self.app_info).context(
        //     SideloadError::InvalidBundle("Failed to write Info.plist".to_string()),
        // )?;
        let mut file = File::create(&info_plist_path).context(SideloadError::InvalidBundle(
            "Failed to write Info.plist".to_string(),
        ))?;
        to_writer_binary(BufWriter::new(&mut file), &self.app_info).context(
            SideloadError::InvalidBundle("Failed to create Info.plist writer".to_string()),
        )?;

        file.sync_all().context(SideloadError::InvalidBundle(
            "Failed to sync Info.plist".to_string(),
        ))?;
        Ok(())
    }

    fn from_dylib_path(dylib_path: PathBuf) -> Self {
        Self {
            app_info: Dictionary::new(),
            bundle_dir: dylib_path,
            app_extensions: Vec::new(),
            frameworks: Vec::new(),
            watch_apps: Vec::new(),
            _libraries: Vec::new(),
        }
    }

    fn collect_dylib_bundles(&self) -> Vec<Bundle> {
        self._libraries
            .iter()
            .map(|relative| Self::from_dylib_path(self.bundle_dir.join(relative)))
            .collect()
    }

    fn collect_nested_bundles_into(&self, bundles: &mut Vec<Bundle>) {
        for bundle in &self.app_extensions {
            bundles.push(bundle.clone());
            bundle.collect_nested_bundles_into(bundles);
        }

        for bundle in self.frameworks.iter().chain(self.watch_apps.iter()) {
            bundles.push(bundle.clone());
            bundle.collect_nested_bundles_into(bundles);
        }
        bundles.extend(self.collect_dylib_bundles());
    }

    pub fn collect_nested_bundles(&self) -> Vec<Bundle> {
        let mut bundles = Vec::new();
        self.collect_nested_bundles_into(&mut bundles);
        bundles.sort_by(|a, b| a.bundle_dir.cmp(&b.bundle_dir));
        bundles.dedup_by(|a, b| a.bundle_dir == b.bundle_dir);
        bundles
    }

    pub fn collect_bundles_sorted(&self) -> Vec<Bundle> {
        let mut bundles = self.collect_nested_bundles();
        bundles.push(self.clone());
        bundles.sort_by_key(|b| b.bundle_dir.components().count());
        bundles.reverse();
        bundles
    }
}

fn assert_bundle(condition: bool, msg: &str) -> Result<(), Report> {
    if !condition {
        bail!(SideloadError::InvalidBundle(msg.to_string()))
    } else {
        Ok(())
    }
}

fn find_dylibs(dir: &Path, bundle_root: &Path) -> Result<Vec<String>, Report> {
    let mut libraries = Vec::new();

    fn collect_dylibs(
        dir: &Path,
        bundle_root: &Path,
        libraries: &mut Vec<String>,
    ) -> Result<(), Report> {
        let entries = isideload_vfs::fs::read_dir(dir).context(SideloadError::InvalidBundle(
            format!("Failed to read directory {}", dir.display()),
        ))?;

        for entry in entries {
            let entry = entry.context(SideloadError::InvalidBundle(
                "Failed to read directory entry".to_string(),
            ))?;

            let path = entry.path();
            let file_type = entry.file_type()
                .context(SideloadError::InvalidBundle(
                    "Failed to get file type".to_string(),
                ))?;

            if file_type.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && name.ends_with(".dylib")
                {
                    // Get relative path from bundle root
                    if let Ok(relative_path) = path.strip_prefix(bundle_root)
                        && let Some(relative_str) = relative_path.to_str()
                    {
                        libraries.push(relative_str.to_string());
                    }
                }
            } else if file_type.is_dir() {
                collect_dylibs(&path, bundle_root, libraries)?;
            }
        }
        Ok(())
    }

    collect_dylibs(dir, bundle_root, &mut libraries)?;
    Ok(libraries)
}

/// Prefix matching must respect identifier components (com.example is not com.example2).
fn remap_identifier(id: &str, old: &str, new: &str) -> String {
    match id.strip_prefix(old) {
        Some(suffix) if suffix.is_empty() || suffix.starts_with('.') => format!("{}{}", new, suffix),
        _ => id.to_string(),
    }
}

fn rewrite_watch_references(info: &mut Dictionary, old: &str, new: &str) {
    for (key, value) in info.iter_mut() {
        if matches!(key.as_str(), "WKCompanionAppBundleIdentifier" | "WKAppBundleIdentifier") {
            if let Value::String(id) = value {
                *id = remap_identifier(id, old, new);
            }
        } else {
            match value {
                Value::Dictionary(dict) => rewrite_watch_references(dict, old, new),
                Value::Array(values) => {
                    for value in values {
                        if let Value::Dictionary(dict) = value {
                            rewrite_watch_references(dict, old, new);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn load_child_bundles(dir: &Path, watch: bool) -> Result<Vec<Bundle>, Report> {
    if isideload_vfs::fs::metadata(dir).is_err() {
        return Ok(Vec::new());
    }
    let mut bundles = Vec::new();
    for entry in isideload_vfs::fs::read_dir(dir).context("Failed to read nested bundles")? {
        let entry = entry.context("Failed to read nested bundle entry")?;
        // Do not follow symlink directories (framework aliases can form cycles).
        if !entry.file_type()?.is_dir() { continue; }
        let path = entry.path();
        if watch {
            if path.extension().is_some_and(|ext| ext == "app") {
                bundles.push(Bundle::new(path)?);
            } else {
                bundles.extend(load_child_bundles(&path, true)?);
            }
        } else if isideload_vfs::fs::metadata(path.join("Info.plist")).is_ok()
            || path.extension().is_some_and(|ext| ext == "appex" || ext == "framework" || ext == "app") {
            bundles.push(Bundle::new(path)?);
        }
    }
    bundles.sort_by(|a, b| a.bundle_dir.cmp(&b.bundle_dir));
    Ok(bundles)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture(id: &str) -> Bundle {
        let mut bundle = Bundle::from_dylib_path(PathBuf::from(id));
        bundle.set_bundle_identifier(id);
        bundle
    }

    #[test]
    fn rewrites_watch_and_nested_extension_links_not_vendor_frameworks() {
        let mut root = fixture("com.example.phone");
        let mut watch = fixture("com.example.phone.watchkitapp");
        watch.app_info.insert("WKCompanionAppBundleIdentifier".into(), "com.example.phone".into());
        let mut ext = fixture("com.example.phone.watchkitapp.extension");
        let mut attributes = Dictionary::new();
        attributes.insert("WKAppBundleIdentifier".into(), "com.example.phone.watchkitapp".into());
        let mut extension = Dictionary::new();
        extension.insert("NSExtensionAttributes".into(), Value::Dictionary(attributes));
        ext.app_info.insert("NSExtension".into(), Value::Dictionary(extension));
        watch.app_extensions.push(ext);
        watch.frameworks.push(fixture("org.vendor.framework"));
        root.watch_apps.push(watch);
        root.rewrite_embedded_bundle_ids("com.example.phone", "com.example.phone.TEAM").unwrap();
        root.set_bundle_identifier("com.example.phone.TEAM");
        let watch = &root.watch_apps()[0];
        assert_eq!(watch.bundle_identifier(), Some("com.example.phone.TEAM.watchkitapp"));
        assert_eq!(watch.app_info["WKCompanionAppBundleIdentifier"].as_string(), Some("com.example.phone.TEAM"));
        assert_eq!(watch.app_extensions()[0].app_info["NSExtension"].as_dictionary().unwrap()["NSExtensionAttributes"].as_dictionary().unwrap()["WKAppBundleIdentifier"].as_string(), Some("com.example.phone.TEAM.watchkitapp"));
        assert_eq!(watch.frameworks()[0].bundle_identifier(), Some("org.vendor.framework"));
        assert_eq!(root.collect_app_id_bundles().len(), 3);
        assert_eq!(root.collect_nested_bundles().len(), 3);
    }

    #[test]
    fn rejects_identifier_prefix_collision() {
        let mut root = fixture("com.example");
        root.app_extensions.push(fixture("com.example2.extension"));
        assert!(root.rewrite_embedded_bundle_ids("com.example", "com.example.TEAM").is_err());
        assert_eq!(remap_identifier("com.example2", "com.example", "new"), "com.example2");
    }
    #[test]
    fn reuse_main_only_reuses_phone_extensions_not_watch_profiles() {
        use crate::sideload::application::Application;
        use crate::sideload::builder::ExtensionsBehavior;
        let mut root = fixture("com.example");
        root.app_extensions.push(fixture("com.example.widget"));
        let mut watch = fixture("com.example.watch");
        watch.app_extensions.push(fixture("com.example.watch.extension"));
        watch.frameworks.push(fixture("org.vendor"));
        root.watch_apps.push(watch);
        let app = Application { bundle: root };
        assert_eq!(app.watch_bundle_ids().len(), 2);
        assert!(!app.watch_bundle_ids().contains("org.vendor"));
        assert!(!app.watch_bundle_ids().contains("com.example.widget"));
        let reuse = app.profile_targets(&ExtensionsBehavior::ReuseMain);
        assert_eq!(reuse.iter().filter(|(_, reuse)| *reuse).count(), 1);
        assert!(reuse.iter().all(|(bundle, reuse)|
            !app.watch_bundle_ids().contains(bundle.bundle_identifier().unwrap()) || !reuse));
        assert!(app.profile_targets(&ExtensionsBehavior::RegisterAll).iter().all(|(_, reuse)| !reuse));
    }

    #[test]
    #[cfg(not(feature = "wasm"))]
    fn discovers_watch_apps_recursively_and_writes_nested_info() {
        let dir = std::env::temp_dir().join(format!("isideload-watch-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let watch = dir.join("Watch/Grouped/Watch.app");
        let ext = watch.join("PlugIns/Watch.appex");
        let framework = ext.join("Frameworks/Shared.framework");
        for (path, id) in [(&dir, "com.test"), (&watch, "com.test.watch"), (&ext, "com.test.watch.ext"), (&framework, "org.vendor")] {
            std::fs::create_dir_all(path).unwrap();
            let info = fixture(id).app_info;
            plist::to_file_binary(path.join("Info.plist"), &info).unwrap();
        }
        std::fs::write(framework.join("libShared.dylib"), []).unwrap();
        let mut root = Bundle::new(dir.clone()).unwrap();
        assert_eq!(root.watch_apps().len(), 1);
        assert_eq!(root.watch_apps()[0].app_extensions()[0].frameworks().len(), 1);
        let sorted = root.collect_bundles_sorted();
        assert_eq!(sorted.iter().filter(|b| b.bundle_dir.extension().is_some_and(|e| e == "dylib")).count(), 1);
        assert_eq!(sorted.last().unwrap().bundle_dir, dir);
        root.rewrite_embedded_bundle_ids("com.test", "com.test.TEAM").unwrap();
        root.set_bundle_identifier("com.test.TEAM");
        root.write_info_recursive().unwrap();
        let info: Dictionary = plist::from_file(ext.join("Info.plist")).unwrap();
        assert_eq!(info["CFBundleIdentifier"].as_string(), Some("com.test.TEAM.watch.ext"));
        std::fs::remove_dir_all(dir).unwrap();
    }

}
