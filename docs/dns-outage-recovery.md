# Automatic encrypted DNS outage recovery

Authorization: already authorized on 2026-10-11. The user explicitly selected
working internet over retaining filtering during a provider outage. This replaces
the ordinary-transport fail-closed requirement of the original local DNS
specification (R08), only within the boundaries below. On 2026-10-12 the user
additionally authorized public Windows/Android releases and local Windows
deployment. The original source-only verification below remains historical
evidence, not a claim that delivery has happened.

## Incident and scope

The selected Control D HTTPS endpoint returned HTTP 503 while independent
Cloudflare DoH answered public queries. Separately, the router's Control D
backend failed even with Windows accept-DNS disabled. Falling back to DHCP is
therefore neither independent nor sufficient. This change fixes the shared
TailDNS client resolver; it does not repair the router or the provider.

## Requirements and acceptance

- O1: For the profile-local **default** resolver, attempt the selected provider
  first. On an HTTP 5xx or network/connection failure, automatically try
  `https://cloudflare-dns.com/dns-query`, using the existing maintained bootstrap
  address table and local route-aware HTTPS transport. Never race healthy
  primary traffic against another provider, use plaintext fallback, or persist
  a substituted provider. A subsequent query tries the selected provider again.
  If the selected endpoint is already the fallback, do not retry it as fallback.
- O2: Preserve successful DNS answers, including NXDOMAIN, REFUSED, empty/block
  answers and DNS SERVFAIL (which can indicate DNSSEC or a domain-specific
  failure). HTTP 4xx, redirects, invalid configuration, certificate rejection and
  malformed responses must not trigger fallback. Never start fallback after
  caller cancellation/deadline. Validate fallback DNS response identity/question
  before accepting it. Both endpoints failing must return normal failure.
- O3: Eligibility comes from the actual matched root route. More-specific split
  routes, authoritative empty routes, MagicDNS, explicit exit-DNS proxy queries,
  lifecycle and managed-DNS gates stay authoritative. The fallback uses the same
  route-aware dialer as the primary, preserving exit-node routing and TLS
  verification. Unavailable Android settings remain a configuration error, not
  an outage-recovery trigger.
- O4: Expose degraded-provider/encrypted-recovery health without private endpoint
  IDs or queried names. Clear it on selected-provider recovery and DNS
  reconfiguration. Applied status documents that automatic recovery may bypass
  filtering; it must not claim provider reachability or fallback use solely from
  configuration. Existing automatic Android settings propagation is unchanged.
- O5: Integrate the exact verified core revision into the current Android fork,
  preserving unrelated local edits. Verify shared resolver behavior on the host,
  Windows build compatibility, Android dependency provenance and a focused
  Android native/binding check. No device state is changed. Record any genuinely
  unavailable verification explicitly, without calling its stage complete.
- O6: Publish immutable next-sequence Windows and Android releases through the
  existing isolated GitHub signing jobs, retaining the official upstream base
  versions. Independently download and verify public assets, checksums, signing
  identities and source provenance before installation.
- O7: Deploy the verified matching Windows payload in the existing Tailscale
  directory, preserving node/login/Tailnet Lock identity, Wintun, profile DNS
  settings and a verified rollback. Verify service, tray, resolver status,
  public DNS and MagicDNS after activation. Android publication does not imply
  Android device deployment.

No extra polling, retry loop, circuit breaker, arbitrary synchronization timer,
or platform DNS mutation is introduced. The existing DNS request context remains
authoritative; this revision does not invent a new blackhole-detection deadline.

## Staged execution and reconciliation

| Stage | Status | Criteria | Evidence / remaining |
| --- | --- | --- | --- |
| 1. Resolver recovery | COMPLETE | O1-O3; O4 health lifecycle | Red test reproduced HTTP 503/connection failure. Focused resolver, transport and health checks pass under the race detector. Real Cloudflare HTTPS recovery passed after injected 503. Negative answers, private/authoritative names, split/explicit routes, cancellation, both-fail, same-provider protection, reconfiguration and return to primary verified. |
| 2. Client integration | COMPLETE | O4 status; O5 Android pin/native and Windows compatibility | Status disclosure regression passes; LocalDNS, DNS manager, CLI and tray checks pass. Windows daemon/CLI/tray compile. Current Android source pins core `45572acd39ad7d2c50600543e17d2ad3d9388745`; its ARM64 API 26 native binding archive compiles with unchanged NDK 23.1.7779620. Existing Android status and health models accept the unchanged API shape/new warning. |
| 3. Final verification and commit | COMPLETE | O1-O5 reconciliation | Final full resolver and DNS-manager package suites passed, including real encrypted recovery. Source/provenance reviewed; core implementation committed at `45572acd3`, Android integration at `e5d44faf7ba2f5fcb1ac348757682b92ce01982b` on `fix/dns-outage-recovery`. Temporary worktree removed after clean-commit verification; reviewed cleanup transaction `03dfbe6ce6e35847f9a13ea12d973377` applied without residuals. |
| 4. Public delivery | ACTIVE | O6; current O1-O5 integration | Refresh focused verification; integrate and publish core, pin that public core in Android main, publish signed assets and independently verify both releases. |
| 5. Local Windows activation | NOT STARTED | O7 | Install the verified public payload in place and verify identity, configuration and live DNS continuity. |

Blockers: none. Tracked deferrals: none. Host transport evidence is not a claim
of phone deployment or a new real-device exit-node test.

## Verification boundaries

Core module: `v1.103.0-pre.0.20261011173409-45572acd39ad`, checksum
`h1:aZBEq3IwPfWuUMJHdYRWohLigNsQhKoxRwIPSCNmQ+s=`. The module was resolved
from the committed local Git repository using process-local Git URL rewriting;
it has not been pushed or published by this task. No local-path replacement is
stored in Android's go.mod. Native verification built `./libtailscale` for
Android ARM64 with CGO and API 26, not a signed APK/AAR release. No Gradle command
was needed or run, and no Kotlin/API schema changed.

Existing request cancellation remains authoritative. An entirely blackholed
primary can consume the existing request deadline before a fallback is possible;
this change adds no speculative timeout or background health polling. It fixes
observable HTTP 5xx and network failure, not every possible cause of no internet.
Router-only DNS failures and an installed official daemon are separate operational
conditions outside this source implementation.

## Final requirement reconciliation

| Requirement | Result and verification |
| --- | --- |
| O1 | Verified primary-first HTTP 503/connection-error recovery, same-provider suppression and immediate return to primary. Real Cloudflare DoH answered after an injected 503. No saved provider substitution or plaintext fallback. |
| O2 | Verified preservation of NXDOMAIN, REFUSED, empty answers and DNS SERVFAIL; HTTP 403/redirect/certificate exclusions; cancellation, both-fail and malformed response rejection; DNS question identity is case-insensitive. |
| O3 | Verified matched-root eligibility, specific/explicit-route exclusion, local/private and authoritative-negative queries without public egress, and stale configuration suppression. Existing route-aware TLS/redirect/bootstrap checks pass; no new real-device exit-node claim. |
| O4 | Verified recovery warning lifecycle and status disclosure without endpoint identifiers. Existing Android/Windows consumers retain their API schema and saved settings behavior. |
| O5 | Verified exact committed core module/hash in Android, ARM64 native compilation, focused backend/client checks and Windows daemon/frontends build. No device, installation, release or remote branch was changed. |

All three original source-implementation stages are COMPLETE. Android
integration was committed on the named local branch to preserve the pre-existing
dirty main checkout. The newly authorized delivery stages above are not complete
until their publication and activation acceptance criteria are verified.
The removed 25.8 MB consisted only of regenerable native validation output and
dependency-download copies; committed source and shared module caches remain.
