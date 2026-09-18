# TailDNS shared-core work

Independent community fork for [Darkaxt/tailscale-android](https://github.com/Darkaxt/tailscale-android). Not an official Tailscale product.

Authority: the Android fork's [local DNS specification](https://github.com/Darkaxt/tailscale-android/blob/main/docs/local-dns-override/SPECIFICATION.md). Initial base: `b5e07cbf538e2558eac3c5fe5c34be288819fff6`, matching its Android dependency.

Status: Stage 1 implementation in progress, not a validated product release. This branch adds profile-local manual DoH preferences, default-only composition, managed-policy checks, a profile-pinned LocalAPI editor endpoint, redacted diagnostics and route-aware DoH transport. More-specific routes remain unchanged.

Known-provider bootstrap uses the existing maintained address table. Generic provider bootstrap sends only its hostname over protected DNS-over-TCP to platform base DNS, outside the exit node. Ordinary queries use the selected HTTPS endpoint without provider fallback. No DERP bootstrap, arbitrary static address list or TLS verification bypass is used.

`TS_TEST_LOCAL_DOH_LIVE=1 go test ./net/dns/resolver -run TestLocalDoHLive -count=1 -v` sends only `example.com` to public Control D, Cloudflare and OpenDNS. This proves host transport, not Android VPN, exit-node routing, automatic following or Guard obsolescence. Those remain staged acceptance requirements in the authoritative plan.
