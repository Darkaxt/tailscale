# Captive-portal release, local deployment and hotel autologin

Authorized 2026-10-04: publish the completed Windows captive-portal patch,
install it locally, then create an hourly hotel-only autologin task ending next
Saturday. This extends delivery authorization, not the DNS behavior contract in
[the portal specification](windows-captive-portal.md).

## Required outcomes

- D1: Publish the exact source through the existing GitHub Windows signing
  pipeline. Preserve the official source version 1.105.0; append fork sequence
  26 only. Independently verify public assets, Ed25519 manifest signature,
  component hashes and exact source identity. This is manifest signing, not
  Authenticode. Do not publish an Android release.
- D2: Update the existing installation in C:\Program Files\Tailscale through
  its authenticated service updater. Preserve service path, node/login/Tailnet
  Lock identity, configured DNS, saved preferences and Wintun. Verify running
  daemon/tray, signed payload hashes, resolver application and DNS after update.
  Use the existing transactional rollback if activation fails.
- D3: After D2 passes, implement a separate local hotel helper, not a TailDNS
  feature. Bind it to the currently connected Wi-Fi SSID/interface and the
  expected hotel's HTTPS portal/site. Check those identities and the cutoff
  before every state-changing request. Never authenticate on another network.
  Obtain fresh splash cookies and follow the normal click-through grant flow;
  do not modify server lifetime parameters, forge device identity or reuse a
  grant from another client. Honor active Windows routing and the exit-node
  kill switch, without proxies, with normal TLS validation and no browser/UI.
  Direct physical binding was a design assumption corrected by live evidence:
  WSAEACCES with the exit-node kill switch active. Do not add firewall exceptions.
- D4: Run hourly without console windows under the current user. Stop before
  2026-10-10 00:00 Europe/Berlin (2026-10-09 22:00 UTC), both by trigger end and
  worker guard. Prevent overlapping workers. Log only sanitized outcomes, not
  cookies, MACs, signed URLs or query parameters. Provide disable/uninstall.
  Do not impose an arbitrary process-kill timeout; network diagnostic deadlines
  belong only to the network boundary.
- D5: Test wrong-network and expiry rejection before scheduling; test cookie/
  redirect handling with controlled HTTP fixtures. Perform the authorized real
  hotel flow, verify connectivity, then trigger the no-console scheduled task
  and inspect its result/log. An accepted grant plus connectivity does not
  establish that an existing 24-hour allowance was extended: report that
  separately unless server-side expiration evidence is available.

## Stages

1. Signed Windows release (D1): COMPLETE.
2. In-place deployment (D2): COMPLETE.
3. Hotel helper and hourly task (D3-D5): COMPLETE.

All stages are COMPLETE. No blockers or required deferrals remain.
The pre-update baseline was 1.105.0-taildns.25, observed on 2026-10-04. User-owned
dirty Android installation scripts remain untouched. Helper source/configuration
are a separate local project; private hotel URLs are not in the public TailDNS
repository. All three stages have been verified.

## Delivery evidence

- D1: GitHub Actions run 37225947416 succeeded and published
  `windows-v1.105.0+26` from `c06ad72ae29aeb1e6f7585a09ef2f809d6c0e6db`.
  A fresh public download passed independent Ed25519, ZIP membership, source,
  base/sequence, checksum and all five executable-hash checks. Release notes
  describe the feature and its validation limits. No local signing key used.
- D2: The authenticated LocalAPI service updater activated the matching signed
  set without UAC. Deployment record and installed version report +26 and the
  exact release commit. Installed hashes match the signed manifest. Before/after
  comparisons pass for node ID/key/IPs, all non-Persist saved prefs, Tailnet Lock
  enabled/signer key, service path and Wintun hash. Both normal tray processes
  run (supervisor and child), public DNS and self MagicDNS resolve, and custom
  DoH is applied with captive mode inactive. No rollback was required.
- D3-D5: The separate local HotelPortalLogin source and authoritative spec deliver
  native Wi-Fi/device guards, current-user DPAPI bootstrap protection, TLS cookie/
  grant handling and hourly temporary scheduling. Final worker source matches
  the installed worker. Controlled unsafe-network/expiry/device/redirect/DHCP
  checks pass, as do live negative network/expiry checks. The real hotel grant
  and both challenge probes succeed; the no-console scheduled run exits 0 with
  a matching sanitized result at 19:45:11 UTC. The hourly task's exported end
  boundary is Saturday 10 October 00:00 local, with IgnoreNew, no wake and an
  independent worker cutoff. Private runtime ACL and disable/uninstall are verified.
  The helper honors Windows routing; it never bypasses the VPN kill switch.
  This is not proof that an already-authorized hotel's 24-hour allowance resets.
  Hotel interception after expiry and IPv6-only operation remain unverified.
  Local-only helper source commit: `b2a7aff46b74475cc6b5a0555498901377fbfd1b`.
  The hotel helper was not added to a public repository or release asset.
- Final host checks still preserve node ID/key/IPs, saved non-Persist preferences,
  Tailnet Lock signer/enabled state, service path and Wintun. +26 exact source,
  running service/tray, custom DoH application, public DNS and MagicDNS pass.
  Reviewed cleanup removed only the public-verification download, diagnostic,
  abandoned MSIX-redirected helper copy and initial test bytecode. Active runtime,
  rollback data and user-owned Android changes remain untouched.
