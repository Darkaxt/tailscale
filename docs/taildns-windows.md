# TailDNS Windows companion

TailDNS adds a profile-local DNS-over-HTTPS default resolver to the forked open-source daemon. The companion is an independently branded command-line frontend; it does not copy or claim to fork Tailscale's proprietary Windows GUI.

The configured endpoint replaces only the default resolver. MagicDNS and eligible more-specific split-DNS routes remain authoritative. Clearing the endpoint restores the normal Tailscale DNS selection. Windows selection is always explicit and never follows Android settings.

## Safety boundary

- `taildns.exe` talks to the daemon's authenticated LocalAPI over its named pipe.
- An official or otherwise unmodified daemon returns an incompatibility error before any edit. The CLI never reports that such a write succeeded.
- The daemon owns validation, profile pinning, policy checks, persistence and effective-state reporting.
- A standard-user test daemon uses a Windows-derived per-user pipe descriptor. An elevated service retains the normal shared service descriptor and LocalAPI actor authorization.
- The test procedure below uses a separate pipe and state directory. It does not stop, overwrite or reconfigure the installed official service.

## Build

From this branch with the repository's required Go toolchain:

```powershell
go build -o D:\Temp\taildns-windows\taildns.exe ./cmd/taildns
go build -o D:\Temp\taildns-windows\taildnsd.exe ./cmd/tailscaled
go build -o D:\Temp\taildns-windows\tailscale-fork.exe ./cmd/tailscale
```

## Explicit isolated test installation

Choose a unique pipe and state directory, then run the forked daemon without replacing the installed service:

```powershell
$testRoot = 'D:\Temp\taildns-windows'
$testPipe = '\\.\pipe\taildns-test'
& "$testRoot\taildnsd.exe" --tun=userspace-networking --socket=$testPipe --statedir="$testRoot\state" --no-logs-no-support --port=0
& "$testRoot\tailscale-fork.exe" --socket=$testPipe up
```

The second command prints a Tailscale device-login URL for this isolated test node. Authentication is an account-bound action; complete it only in the intended tailnet.

## Configure and inspect

The CLI autosaves through the backend. There is no separate save command:

```powershell
& "$testRoot\taildns.exe" --socket $testPipe status
& "$testRoot\taildns.exe" --socket $testPipe set 'https://resolver.example/dns-query'
& "$testRoot\taildns.exe" --socket $testPipe --json status
& "$testRoot\taildns.exe" --socket $testPipe clear
```

`set` succeeds only after the daemon confirms both the saved endpoint and its applied state. A saved-but-inactive configuration is returned as an error with the backend reason rather than as a successful apply. Invalid endpoints are rejected before a write.

## Removal and restoration

Clear the override before removing an authorized test node, then stop only the isolated daemon and delete only its selected test directory:

```powershell
& "$testRoot\taildns.exe" --socket $testPipe clear
& "$testRoot\tailscale-fork.exe" --socket=$testPipe down
```

If the isolated daemon is still running, stop that exact process after recording its PID. Do not stop the installed `Tailscale` service. Remove the temporary test node from the tailnet console when it is no longer required. The official client remains on its original service, state and configuration throughout this procedure.

## Verification status

Focused client, LocalAPI, CLI and Windows named-pipe tests pass. A Windows host test also proves that `status` and `set` against the installed unmodified daemon return an explicit incompatibility error and perform no edit. Full isolated-node DNS, restart persistence, route and exit-node evidence is recorded in the Android fork's staged validation documents after the account-bound test login completes.
