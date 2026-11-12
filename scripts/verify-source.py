#!/usr/bin/env python3
"""Source guard checks only. This does not compile or exercise a real device."""
import json
import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

def read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def require(condition, message):
    if not condition:
        raise SystemExit('SOURCE GUARD FAILED: ' + message)

host = tomllib.loads(read('src-tauri/Cargo.toml'))
lib = tomllib.loads(read('vendor/isideload/Cargo.toml'))
lock = tomllib.loads(read('src-tauri/Cargo.lock'))
conf = json.loads(read('src-tauri/tauri.conf.json'))
require(host['package']['version'] == '2.4.1', 'iloader baseline changed')
require(lib['package']['version'] == '0.5.2', 'isideload baseline was downgraded')
require(host['dependencies']['isideload']['path'] == '../vendor/isideload', 'not using local incremental patch')
require(host['dependencies']['idevice']['version'] == '=0.1.68', 'device library not pinned')
for name, version in [('idevice', '0.1.68'), ('isideload', '0.5.2')]:
    versions = [p['version'] for p in lock['package'] if p['name'] == name]
    require(versions == [version], f'unexpected {name} lock versions: {versions}')
require(conf['identifier'] != 'me.nabdev.iloader', 'official app data namespace reused')
require(conf['plugins']['updater']['endpoints'] == [], 'remote updater enabled')
require(conf['bundle']['createUpdaterArtifacts'] is False, 'publishing enabled')
for path in ['vendor/isideload/src/sideload/watch_install.rs', 'src-tauri/src/watch_transport.rs']:
    require((ROOT / path).is_file(), f'missing implementation: {path}')
secure = read('src-tauri/src/secure_storage.rs')
require('FsStorage::new' not in secure, 'unencrypted secret fallback restored')
require('KEYRING_SERVICE' in secure, 'credential namespace missing')
sign = read('vendor/isideload/src/sideload/sideloader.rs')
policy = read('vendor/isideload/src/sideload/application.rs') + read('vendor/isideload/src/sideload/bundle.rs')
for required in ['ExtensionsBehavior::ReuseMain', 'ExtensionsBehavior::RegisterAll']:
    require(required in policy, f'extension profile policy lost: {required}')
for required in ['ExtensionsBehaviorSelection', 'pairing_file', 'device_udid']:
    require(required in sign, f'new signing behavior lost: {required}')
platform_source = read('vendor/isideload/src/dev/device_type.rs')
require('DeveloperDeviceType::Watchos => "ios/"' in platform_source, 'Watch developer service URL is not the iOS namespace')
require('DTDK_Platform' in platform_source, 'Watch platform body marker missing')
for name, calls in [('devices.rs', 2), ('app_ids.rs', 5), ('app_groups.rs', 4)]:
    source = read('vendor/isideload/src/dev/' + name)
    require('dev_url(' not in source, f'platform body builder bypassed in {name}')
    require(source.count('= dev_request(') == calls, f'platform request coverage changed in {name}')
profile_source = read('vendor/isideload/src/sideload/watch_profile.rs')
require('ProvisionedDevices' in profile_source and 'TeamIdentifier' in profile_source, 'Watch profile identity/device checks missing')
require('suffix != bundle_id' in profile_source, 'exact Watch bundle identity check missing')
install_source = read('vendor/isideload/src/sideload/watch_install.rs')
require(install_source.count('watch_profile::validate_install_profiles(') == 2, 'USB/RSD active-Watch profile checks missing')
require(install_source.count('watch_lockdown.get_value(Some("UniqueDeviceID"), None)') == 2, 'Watch identity read was replaced by phone/registry identity')
host_source = read('src-tauri/src/sideload.rs')
require(host_source.index('watch_profile::validate_install_profiles(') < host_source.index('Installing iPhone companion'), 'Watch profile preflight must precede phone upload')
require(not (ROOT / 'src-tauri/src/renewal').exists(), 'old renewal system imported')
require(not (ROOT / 'src-tauri/src/renewal_commands.rs').exists(), 'old renewal commands imported')
print(json.dumps({'sourceGuards':'passed', 'compiled':False, 'hardwareTested':False,
                  'freeAccountVerified':False, 'hermesVerified':False}, indent=2))
