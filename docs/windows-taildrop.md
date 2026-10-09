# Windows Taildrop receive repair

Authoritative specification, 2026-10-09. Authorization: implement, publish a
public Windows release and deploy locally. No Android release or settings change.

## Evidence and required behavior

The Fold7 submitted Scan_20261009_191828.jpg to Beacon. LocalAPI exposes a
completed 971,101-byte JPEG, but the replacement Windows tray ignores Taildrop
events and its Windows notification implementation is a no-op.

- T1: The interactive Windows tray receives completed inbox files at startup,
  service reconnection and file-arrival events. One serialized worker, independent
  of menu rebuilds, uses authenticated LocalAPI. No polling, arbitrary sleeps,
  privileged filesystem access or daemon/settings/identity changes.
- T2: Resolve the current user's Windows Downloads known folder, including
  redirected locations. Copy into a private staging file there, apply Internet
  quarantine, verify the complete declared size, flush/close, and publish without
  overwriting existing files (numbered suffix on conflict). Reject unsafe Windows
  basenames, path traversal, device names and alternate data streams. Remove only
  owned staging files on failure; preserve the daemon inbox until publication.
- T3: Acknowledge the inbox only after successful publication. Errors remain
  visible and retryable through a tray action; do not spin on repeated failure.
  An acknowledgement failure leaves the saved file and inbox intact. Explicit
  retry/restart can create a numbered duplicate rather than risk losing a file.
- T4: Send a native Windows arrival notification after publication, with the
  saved location; surface receive errors. Do not claim notification visibility
  when Windows suppresses it. Provide Open Downloads and Receive pending files.
  Never open received content automatically. Existing other-platform behavior
  and the tray supervisor remain unchanged.
- T5: Publish the verified source through the existing GitHub Ed25519-manifest
  signing pipeline, append only the next fork sequence to VERSION.txt's upstream
  version. Independently download/verify public assets, signature and exact source.
  Deploy with the existing transactional native installer (invoked by the
  service updater or elevated directly from the verified payload); preserve node/login/
  Tailnet Lock identity, DNS preferences, service registration and Wintun. Verify
  installed signed hashes, service/tray health, DNS, and the actual waiting photo
  in Downloads. Roll back through the existing installer if activation fails.

Win32 references: [notification API](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shell_notifyiconw),
[notification structure](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-notifyicondataw),
[non-overwriting publication](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

## Compact stage ledger

1. Receive/notification implementation and focused verification (T1–T4): COMPLETE.
   Acceptance: regression tests demonstrate event/startup handling, exact-copy /
   failure safety, quarantine, collisions, unsafe names and native notification
   data; tray and installer contracts pass. Verified native Windows LocalAPI HTTP
   integration and real-filesystem tests cover complete-copy-before-ack,
   short/long/changed-length/error/cancel preservation, numbered collisions,
   Internet quarantine, reserved/unsafe names, event coalescing and graceful
   worker shutdown. Native notification layout and Unicode boundaries pass.
   Full tray, supervisor, updater/provider and installer contracts pass; the
   GUI-subsystem tray builds. No production source outside the tray changed.
   Remaining: none for T1–T4; installed receive workflow verified in Stage 2.
2. Signed public release and in-place validation (T5): COMPLETE.
   Acceptance: exact public source/signature/payload proof and installed workflow
   checks, including the waiting photo. Depends on Stage 1 COMPLETE.
   Delivery detail: use the same native installer directly with elevation after
   public verification, avoiding a second full download over the slow connection.
   This does not change the transactional preservation or rollback requirements.

## Public delivery and installed evidence

- Public release: [windows-v1.105.0+29](https://github.com/Darkaxt/tailscale/releases/tag/windows-v1.105.0%2B29),
  source `b11449f4da82808edce58d5a4ceb663a394447d2`, successful GitHub Actions
  run [37967438436](https://github.com/Darkaxt/tailscale/actions/runs/37967438436).
  This is a normal public release, not a draft or pre-release. Upstream base
  remains `1.105.0`; only the fork sequence increased to 29.
- Independently downloaded all public assets. Verified SHA256SUMS, the existing
  pinned Ed25519 key/signature, exact tag/source/version, ZIP membership, all five
  payload hashes/sizes, amd64 PE images, GUI subsystem and installer UAC manifest.
  ZIP SHA256: `52d678f0917f340440b662b8eb279bfbc3fd49d8f05636c2fbcfe8ef162a2a93`.
  Manifest signing is not Authenticode signing.
- Elevated native installer update exited successfully on 2026-10-09. Installed
  four runtime payloads match the signed manifest in the existing Tailscale
  directory. CLI source/version and active deployment record match the release.
  Service is Running; the installed supervisor and child are running in the
  interactive session, with both executable identities independently checked.
- Private before/after comparison passed for node/login identity, Tailnet Lock
  signer state, non-Persist preferences, resolver configuration, service image
  path and Wintun. Public DNS and self MagicDNS resolution passed.
- The actual previously waiting 971,101-byte photo appeared automatically in the
  redirected Downloads known folder on tray startup. Its SHA256 matched the
  pre-deployment inbox bytes, Zone.Identifier contains ZoneId=3, and its inbox
  entry was acknowledged. No manual file retrieval was used for delivery.
- Windows accepted a native notification probe using the installed tray's
  existing window/icon. Banner visibility is governed by Windows and is not
  claimed. Arrival/error ordering is covered by receiver integration tests.
- No Android build, installation, device settings change or identity reset was
  performed. Private baseline, signed manifest and verification scripts are
  retained locally outside the repository; account data and photo contents are
  not published.

Verification commands: `go test ./client/systray ./cmd/taildns-ipn -count=1`,
`go test ./clientupdate/taildnsupdate ./feature/clientupdate ./cmd/taildns-installer -count=1`,
and `go build -buildvcs=false -trimpath -ldflags '-H windowsgui' ./cmd/taildns-ipn`.
No Gradle command, source database write, device installation or identity change.

Final reconciliation: T1–T5 satisfied and verified. Blockers: none. Tracked
deferrals: none. Both implementation and public/local delivery are COMPLETE.
