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
  grant from another client. Use physical-interface-bound connections without
  proxies, normal TLS validation, and no browser/UI automation.
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

1. Signed Windows release (D1): ACTIVE.
2. In-place deployment (D2): NOT STARTED.
3. Hotel helper and hourly task (D3-D5): NOT STARTED.

Only one stage is ACTIVE. No blockers or required deferrals currently recorded.
The installed baseline is 1.105.0-taildns.25, observed on 2026-10-04. User-owned
dirty Android installation scripts remain untouched. Helper source/configuration
will be a separate local project; private hotel URLs will not enter the public
TailDNS repository. Final completion requires all three stages verified.
