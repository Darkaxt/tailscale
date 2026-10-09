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
  Deploy with the existing transactional service updater; preserve node/login/
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
   Remaining: none for T1–T4; native visible workflow is required by Stage 2.
2. Signed public release and in-place validation (T5): ACTIVE.
   Acceptance: exact public source/signature/payload proof and installed workflow
  checks, including the waiting photo. Depends on Stage 1 COMPLETE.

Verification commands: `go test ./client/systray ./cmd/taildns-ipn -count=1`,
`go test ./clientupdate/taildnsupdate ./feature/clientupdate ./cmd/taildns-installer -count=1`,
and `go build -buildvcs=false -trimpath -ldflags '-H windowsgui' ./cmd/taildns-ipn`.
No Gradle command, source database write, device installation or identity change.

Blockers: none. Tracked deferrals: none. No completion claim until the assigned
criteria pass; publication and deployment remain part of this task.
