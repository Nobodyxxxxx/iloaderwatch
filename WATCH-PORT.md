# Watch port — unofficial experimental build

**Not an official iloader release.** Upstream: https://github.com/nab138/iloader and https://iloader.app.

Base: iloader **2.4.1**, with incremental local changes to **isideload 0.5.2** and pinned **idevice 0.1.68**. This is not the old 2.3.4 fork with a new filename.

## Watch developer API fix 1 (2026-11-11)

The first compiled build (`c8ad22cb97f0`) incorrectly used the non-existent `QH65B2/watchos/` route and omitted the Watch platform body field. A user reported HTTP 404 at `watchos/listDevices.action`; this is an integration bug, not evidence that a free Apple account was rejected.

Fix 1 routes Watch device/App-ID/profile/app-group operations through `QH65B2/ios/` with `DTDK_Platform=watchos` in the XML plist body. Eleven typed call sites share one URL/body constructor. Regression tests cover the exact routes, serialized Watch field, preservation of device IDs/groups, and unchanged default iOS/tvOS/Any behavior. No identity, profile or entitlement is relabeled as iOS merely to bypass an error. App data/credential namespaces remain unchanged, so updating the EXE does not require deleting the phone or Watch app.

This fix removes the identified request-format defect; actual Apple authorization and device installation still require verification. Do not uninstall HermesEnabler or reset its backup to resolve this HTTP 404.

## Watch profile fix 2 (2026-11-12)

The first API fix progressed past HTTP 404, but our added guard then rejected any serialized `Platform` list without the literal `watchOS`. This local error did not establish that Apple had rejected the account or that a usable Watch profile had been issued. The error did not report the actual list value.

Apple's [development-profile documentation](https://developer.apple.com/help/account/provisioning-profiles/create-a-development-provisioning-profile/) groups iOS and watchOS under `iOS App Development`. [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles) also states these profile internals are not API. Do not use a family label alone as proof of either a valid or invalid Watch authorization.

Fix 2 accepts iOS-family or explicit watchOS metadata only with exact Watch bundle identity. It verifies the selected team and profile App ID prefix, rejects phone/wildcard identities and incompatible tvOS/macOS metadata, and checks the unmodified embedded `ProvisionedDevices` against actual paired Watches before phone upload. The Watch transport repeats device authorization after authenticating the active Watch's own `UniqueDeviceID`, before starting the Watch zip upload. Registry preflight alone is not proof of which paired Watch is active. Missing or mismatched device authorization fails closed without logging raw profiles or UDIDs.

No CMS bytes, entitlements, Bundle ID, developer account, pairing record, data directory or credential namespace is rewritten to bypass this check. A profile that really does not authorize the active Watch will still be rejected with a more specific error. No successful free-account or hardware installation is claimed.

## USB pairing diagnostic candidate 3 (2026-11-12)

User feedback from the Profile fix 2 build: the phone installed, but the Watch path timed out inside `LockdownClient::pair` through the RSD CompanionProxy. The Watch developer mode was fully enabled. The supplied log tail (`RSDCheckin`, `StartService`, `StopForwardingServicePort`, `ComandSuccess`) was cleanup after timeout, not evidence of successful Watch pairing. The grey Watch icon is not proof of a complete Watch install.

The [fork.2 release](https://github.com/AndreySemjonov/iloader/releases/tag/v2.3.4-fork.2) adds a 180-second **post-upload** status timeout; its diff does not fix Pair. The screenshots describe a separate modified CLI and S10 testimonial, but do not provide a reproducible CLI source or command. Authentication/anisette and Watch App Groups are important but are not established causes of this pre-upload Pair timeout. Do not revoke certificates or change accounts based on that post.

Candidate 3 corrects a reference-path difference: USB selection now explicitly uses the authenticated USB provider and ordinary `com.apple.companion_proxy`, as the reference fork does. The previous mandatory USB CoreDeviceProxy/RSD path was unverified on this device. There is no silent fallback, automatic uninstall, second phone install, trust bypass or increased timeout. The existing RSD library entry remains available but is not called by this USB host path. This route correction is a candidate, **not proof of the actual timeout's root cause or a successful device fix**.

Shared USB/RSD pairing now reports fixed-label stages: `lockdown_query_type`, `device_public_key`, `wifi_address`, `pair_build_or_trust`, `watch_session`, `authenticated_watch_identity`. Read-only preflights distinguish a silent forwarded socket from a later Pair deadline. The original idevice `pair()` still constructs certificates and handles pending trust. Its internal key reads/certificate generation/trust wait are not separately observed; a `pair_build_or_trust` timeout must not be described as user refusal. No loop around `pair_once` or re-use of phone certificates as Watch certificates is introduced.

Both file and UI logs suppress low-level protocol INFO/DEBUG dumps that may contain complete pairing records. Dedicated Watch diagnostics print only stage/transport/counters and numeric device error codes, never raw PairRecord, public/private keys, profile bytes, UDIDs or tokens. Error/UI content outside this filtering still requires review before sharing.

Tests use fake in-memory connections for real idevice QueryType framing, silent socket deadlines, phase labels and private-payload canaries; they do not perform real pairing or cryptographic/device integration. The exact App ID/team/prefix checks and both actual-Watch `ProvisionedDevices` checks from Profile fix 2 remain in place.

## Verification status

Until a successful Windows Actions run produces an executable, this repository is **work in progress, not a compiled deliverable**. Source-guard checks are not compilation. The generated BUILD.json distinguishes a failed build from a compiled-and-unit-tested build.

Even a successful build is **not proof** of installation using a free Apple ID, actual operation on Series 9/watchOS 27.0, or Hermes functionality. These require separate device tests. No Apple account is used by CI.

## Scope

- Embedded companion apps under `Watch/*.app` only; no promise of standalone Watch-only app support.
- Keep the 0.5.2 callback, ordinary extension, special application and AltStore handling architecture.
- Register and provision phone and Watch targets for their real platforms; no iPhone-profile reuse for Watch code.
- Manual installation with a paired USB iPhone; Watch forwarding uses the authenticated direct USB CompanionProxy route. The ordinary device-selection pairing setup is retained, but the Watch install no longer forces a CoreDeviceProxy/RSD tunnel.
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
