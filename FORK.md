# TailDNS shared core

Independent community core fork for [TailDNS](https://github.com/Darkaxt/TailDNS). Not an official Tailscale product.

The authoritative implementation is maintained on `main`. Its requirements and validation evidence live in the Android fork's [local DNS specification](https://github.com/Darkaxt/TailDNS/blob/main/docs/local-dns-override/SPECIFICATION.md).

This fork adds profile-local Android DNS-provider following, manual DoH preferences for non-Android clients, default-only DNS composition, managed-policy checks, a profile-pinned LocalAPI editor endpoint, redacted diagnostics, route-aware DoH transport, and the independently branded `taildns` Windows CLI. More-specific DNS routes remain unchanged.

Known-provider bootstrap uses the existing maintained address table. Generic provider bootstrap sends only its hostname over protected DNS-over-TCP to platform base DNS, outside the exit node. Ordinary queries use the selected HTTPS endpoint without provider fallback. No DERP bootstrap, arbitrary static address list or TLS verification bypass is used.

The upstream Tailscale package/module names are retained where compatibility requires them. Original copyright, license, and trademark attribution remain intact.
