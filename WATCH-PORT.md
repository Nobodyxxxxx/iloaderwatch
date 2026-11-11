# Watch port — unofficial experimental build

**Not an official iloader release.** Upstream: https://github.com/nab138/iloader and https://iloader.app.

Base: iloader **2.4.1**, with incremental local changes to **isideload 0.5.2** and pinned **idevice 0.1.68**. This is not the old 2.3.4 fork with a new filename.

## Watch developer API fix 1 (2026-11-11)

The first compiled build (`c8ad22cb97f0`) incorrectly used the non-existent `QH65B2/watchos/` route and omitted the Watch platform body field. A user reported HTTP 404 at `watchos/listDevices.action`; this is an integration bug, not evidence that a free Apple account was rejected.

Fix 1 routes Watch device/App-ID/profile/app-group operations through `QH65B2/ios/` with `DTDK_Platform=watchos` in the XML plist body. Eleven typed call sites share one URL/body constructor. Regression tests cover the exact routes, serialized Watch field, preservation of device IDs/groups, and unchanged default iOS/tvOS/Any behavior. No identity, profile or entitlement is relabeled as iOS merely to bypass an error. App data/credential namespaces remain unchanged, so updating the EXE does not require deleting the phone or Watch app.

This fix removes the identified request-format defect; actual Apple authorization and device installation still require verification. Do not uninstall HermesEnabler or reset its backup to resolve this HTTP 404.

## Verification status

Until a successful Windows Actions run produces an executable, this repository is **work in progress, not a compiled deliverable**. Source-guard checks are not compilation. The generated BUILD.json distinguishes a failed build from a compiled-and-unit-tested build.

Even a successful build is **not proof** of installation using a free Apple ID, actual operation on Series 9/watchOS 27.0, or Hermes functionality. These require separate device tests. No Apple account is used by CI.

## Scope

- Embedded companion apps under `Watch/*.app` only; no promise of standalone Watch-only app support.
- Keep the 0.5.2 callback, ordinary extension, special application and AltStore handling architecture.
- Register and provision phone and Watch targets for their real platforms; no iPhone-profile reuse for Watch code.
- Manual installation with a paired iPhone; the experimental transport starts from USB and uses RemotePairing/RSD.
- No old fork automatic renewal, background saved-password login, startup tasks or tray subsystem.
- Separate application-data and credential namespaces. No silent unencrypted-filesystem fallback when secure storage is unavailable.
- Automatic binary updates disabled. No automatic release publishing, paid runners or code signing certificate use.

## Build on Windows

Prerequisites: Visual Studio 2022 C++ Build Tools, the Windows SDK, Rust 1.98.1 MSVC toolchain, Bun 1.4.2, Perl and make (for native dependencies). WebView2 Runtime is needed to run the resulting GUI. Apple Mobile Device drivers and device trust/Developer Mode may be required for device operations.

Commit the source before building. In PowerShell:

```powershell
./scripts/Build-Watch-Windows.ps1
```

The workflow `.github/workflows/watch-windows.yml` runs the same script on a standard Windows x64 runner. On success, `out/watch-windows/` contains the experimental EXE, SHA256SUMS.txt, BUILD.json, test/build logs and lockfiles. CI run URL and exact source commit are recorded. This build has no Authenticode signing certificate and must not claim official publisher identity.

A failed run may upload diagnostic logs and a `BUILD.json` with `status=failed`; **that artifact is not a successful EXE release**. Never rename the old fork EXE or a non-Windows artifact to fake success.

## Safety for any future hardware test

Do not enter a primary Apple ID merely to test an experimental build. A separate account only reduces account impact; it does not protect the paired phone or PC from all risks. Keep required entitlements intact. If a free team cannot obtain a matching profile, fail with an explicit error rather than silently stripping capabilities. Stop on credential-store errors. Do not share pairing files, private keys or unredacted logs.

For HermesEnabler, keep its bundle ID/account stable and follow its own backup/restore instructions. This installer does not establish Hermes compatibility or make modifying system data risk-free.

## Third-party attribution

iloader source and original assets: nab138, MIT source license plus LICENSE-BRANDING. isideload 0.5.2: nab138, MIT. Watch companion transport/signing reference: Rzbck/Data_C0re_ PR #22 (`d898f5f36a463b216fe5cfb2b8fa4073fa1e4b30`) and the audited AndreySemjonov fork (`7888d93421460b3065914e2c831e9f29cabea40b`), preserving their original license and attribution. Their reference code is adapted rather than used to downgrade the 0.5.2 package.
