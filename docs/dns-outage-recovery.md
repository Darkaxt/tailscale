# Automatic encrypted DNS outage recovery

Authorization: already authorized on 2026-10-11. The user explicitly selected
working internet over retaining filtering during a provider outage. This replaces
the ordinary-transport fail-closed requirement of the original local DNS
specification (R08), only within the boundaries below. Publication and device
deployment are not part of this implementation request.

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

No extra polling, retry loop, circuit breaker, arbitrary synchronization timer,
or platform DNS mutation is introduced. The existing DNS request context remains
authoritative; this revision does not invent a new blackhole-detection deadline.

## Staged execution and reconciliation

| Stage | Status | Criteria | Evidence / remaining |
| --- | --- | --- | --- |
| 1. Resolver recovery | COMPLETE | O1-O3; O4 health lifecycle | Red test reproduced HTTP 503/connection failure. Focused resolver, transport and health checks pass under the race detector. Real Cloudflare HTTPS recovery passed after injected 503. Negative answers, private/authoritative names, split/explicit routes, cancellation, both-fail, same-provider protection, reconfiguration and return to primary verified. |
| 2. Client integration | ACTIVE | O4 status; O5 Android pin/native and Windows compatibility | Core status disclosure, exact Android pin/native and Windows build verification remain. |
| 3. Final verification and commit | NOT STARTED | O1-O5 reconciliation | Review affected package results, provenance and cleanup; commit completed scope. |

Blockers: none. Tracked deferrals: none. Host transport evidence is not a claim
of phone deployment or a new real-device exit-node test.
