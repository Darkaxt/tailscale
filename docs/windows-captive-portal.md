# Windows captive-portal login — authoritative specification

Authorized: 2026-10-04, user request to implement automatic hotel Wi-Fi login
compatibility and probe `eu.network-auth.com`. This is a Windows-only extension
to the local DNS contract, not ordinary resolver failover. Implementation,
verification and commit are authorized; publication and host installation are
not part of this request.

## Requirements

- CP1: Detect a captive portal on the current physical default network with
  interface-bound, DNS-independent HTTP probes. Only a valid HTTP(S) redirect
  from a known connectivity probe is positive evidence. DNS errors, timeouts,
  HTTP errors, proxy authentication and ordinary outages do not enable bypass.
- CP2: While a confirmed portal requires login, temporarily use that network's
  explicit DNS servers for default queries. Preserve eligible MagicDNS,
  authoritative empty and more-specific routes. Never use a public fallback or
  the portal hostname as a permanent DNS exception. Root catch-all routes must
  not defeat the temporary resolver. Normal custom DoH remains fail-closed.
- CP3: Temporarily pause exit-node routing where needed to reach the portal.
  Keep all stored preferences, selected exit node, login and machine state
  untouched. While login mode is active, default DNS is plaintext to the local
  network and ordinary internet traffic can be direct; disclose this explicitly.
- CP4: Bind transient state and probe results to the current profile and physical
  network generation. Restore configured DNS/routing on positive validation of
  the same network, a network/profile change, disconnect, logout or shutdown.
  An inconclusive probe must never be interpreted as successful login. Respect
  managed DNS/exit-node policies and the upstream lifecycle gates.
  Preserve feature-omission builds and keep detector dependencies out of
  non-Windows backend builds.
- CP5: Report active login mode through LocalAPI, tray and health state, without
  recording portal URLs, login tokens, provider IDs or user DNS questions in logs.
  Monitor network/health events; periodic probes during login are diagnostic only,
  not expiry-based restoration. Probe deadlines are confined to HTTP diagnostics.
- CP6: Verify redirect detection, outage rejection, login/restoration, stale-result
  rejection, preference preservation, routing/DNS composition and Windows socket
  binding in focused tests. Build affected Windows deliverables. Read-only real
  DNS/TLS/HTTP probes of `eu.network-auth.com` supplement but do not substitute
  for portal simulation. Physical hotel authentication and IPv6-only hotel tests
  unavailable here are disclosed validation gaps, not invented proof.

## Staged plan and reconciliation

1. Detector and evidence (CP1, detection part of CP6): COMPLETE.
   Prove positive redirects vs valid/inconclusive replies and interface binding.
2. Backend integration (CP2–CP5, integration part of CP6): COMPLETE.
   Prove temporary DNS/routing, preserved saved choices, policies, generation
   ownership, restoration and visible status with the real engine configuration.
3. Final verification (CP6): COMPLETE.
   Focused regression suite, Windows builds, real server probe, source review,
   complete reconciliation and commit. No delivery of a partial implementation.

Blockers: none. Required deferrals: none. Unavailable physical captive network is
a disclosed verification limitation; controlled redirect/login tests are required.

Stage 2 closure evidence: controlled redirects drive the actual userspace test
engine to the physical-network DNS configuration without exit default routes;
two independent valid responses restore custom DoH and the saved exit routes.
Preferences remain unchanged. Focused policy, stale profile/generation,
lifecycle, LocalAPI, tray, existing DNS and exit-node regressions pass. Real
IPv4/IPv6 loopback socket tests pass. Explicit `go list -deps` gates for Linux
and Windows with `ts_omit_captiveportal,ts_include_cli` contain no captive-portal
dependency (the repository's dependency test skips Windows hosts, so its skip
was not counted as verification). Final builds and race verification belong
to stage 3.

## Initial server evidence

2026-10-04: system DNS resolves `eu.network-auth.com` through its public CNAME
chain. An HTTPS HEAD request passes certificate validation and returns nginx
HTTP 404 at `/`. The supplied tokenized splash URL returns HTTP 200, HTML with
login/splash content, over certificate-verified HTTPS. Tokens were not saved and
no authentication submitted. A root-path 404 is not portal evidence, login success, or proof
that a hotel-specific path is accessible before authentication. No form submitted.

References: [Microsoft NCSI](https://learn.microsoft.com/en-us/windows-server/networking/ncsi/ncsi-overview),
[Windows interface binding](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options),
[Tailscale portal detection](https://tailscale.com/docs/integrations/captive-portals).

## Final reconciliation and verification — 2026-10-04

- CP1: SATISFIED. Redirect/invalid-location/error/challenge tests pass; the
  detector does not follow login redirects. Real IPv4 and IPv6 Windows loopback
  sockets verify interface selection and the different socket-option byte order.
  The login network selector itself remains IPv4-default-only.
- CP2–CP3: SATISFIED. `TestWindowsCaptivePortalRealEngineTransition` runs, without
  skipping, against actual HTTP fixture servers and the real userspace test
  engine. Temporary network DNS and removal of exit default routes are observed;
  positive validation restores custom DoH and both exit default routes. The test
  does not install a TUN or reconfigure the user's service. Composition tests
  retain eligible specific and authoritative empty routes and saved preferences.
- CP4: SATISFIED. Policy, lifecycle and network/profile ownership regressions pass,
  including A -> B -> A generation fencing. A failed post-probe network inspection
  cannot commit a result or count as login completion. Linux and Windows omission
  dependency checks pass. Detector imports remain behind the Windows build gate.
- CP5: SATISFIED. LocalAPI reports requested/applied login mode distinctly from
  custom DoH application. Tray status uses this reason and refreshes on health
  changes. The complete tray and tray-supervisor component suites pass. Probe
  results carry no redirect URL, and the runtime detector discards diagnostic
  logging. No supplied splash tokens or HTML are stored in the repository.
- CP6: SATISFIED within the stated validation boundary. Focused Windows race tests
  pass for detector/backend transitions. Existing local DNS, DNS composition,
  exit-node routing, LocalAPI and no-leak/fail-closed DoH regressions pass.
  Windows amd64 daemon, CLI, resolver and GUI-subsystem tray compile from this
  worktree with Go 1.27.1. These are unsigned, unstamped verification outputs,
  not release packages; they are expendable and removed after verification.
  The real DNS/TLS/HTTP evidence above is not hotel-login or ticket-renewal proof.

All three stages are COMPLETE; blockers and required deferrals are zero. This
record is finalized by the commit containing it. No Android behavior, upstream
version, host installation, scheduled task or published release is changed.
Physical hotel interception/authentication, Windows OS/TUN behavior on that hotel
network and IPv6-only network selection remain explicitly unverified. The next
delivery step, when authorized, is the existing signed Windows release pipeline
and in-place deployment, not replacement of login/machine state.
