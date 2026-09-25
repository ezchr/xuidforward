# xuidforward

An [Endstone](https://github.com/EndstoneMC/endstone) plugin that forces a Bedrock Dedicated
Server to register the real XUID from a self-signed (offline) login, so relayed players get their
own persistent player record instead of a fresh, empty one on every join.

## The problem it solves

Native BDS discards the XUID of any login whose chain is self-signed (`AuthenticationType` 2)
rather than signed by Xbox Live. With `online-mode=false` it lets the player in, but files them
under a blank XUID, so their inventory, position, stats and permissions reset on every reconnect.

This bites any setup where a proxy or relay logs into BDS on the player's behalf with a re-signed
offline chain — a common pattern for bringing Bedrock (or, via Geyser, Java) players onto a BDS
world through Xbox Live's Friends tab. The player's real XUID is present in the login chain the
relay sends; BDS simply throws it away.

BDS is closed source and has no config option or script hook that runs before identity is
resolved, so this can't be fixed from the relay side alone.

## How it works

The plugin has two halves:

1. **Python plugin** (`python_plugin/endstone_xuidforward`) — uses Endstone's public
   `PacketReceiveEvent` to read the incoming Login packet, pull the real XUID and name out of the
   login chain, and *stage* that identity for the login about to be validated.
2. **Native shim** (`plugin/`, `shim/`) — a small `.so` loaded into the BDS process via `ctypes`.
   It patches a single call in BDS's login path and, for a login whose XUID field BDS left empty,
   writes the staged real XUID into `PlayerAuthenticationInfo` before player storage is selected.
   Endstone ships no C++ SDK artifact, which is why the native part is a standalone shim rather
   than a C++ plugin.

The native patch is **evidence-gated**: it carries a per-build profile (exact executable size plus
the exact bytes expected at the patch site) and refuses to patch anything that does not match, so
a BDS update makes it fail closed rather than corrupt a running server. Profiles live in
`plugin/profiles/`; `plugin/tools/verify.cpp` and `tools/elfscan.py` help build one for a new
BDS version.

## Security model

`online-mode=false` means BDS trusts whatever identity it is handed, so the BDS listener **must
not be reachable from the public internet** — bind it to loopback and let the relay's Xbox Live
front door be the real authentication boundary. The plugin enforces this itself:

- An identity is only staged when the login **arrives from this machine** (the relay is local).
- It stages only under the **verified** name from the login chain, never a client-written field.
- The hook only ever fills an **empty** XUID — a genuine Xbox login's XUID is never overwritten.
- Staged identities are consumed on use, expire in seconds, and are all dropped the moment a
  login arrives from off-box.
- `SelfSignedId == uuid5(namespace, XUID)` is checked as a **consistency** signal, not
  authentication — the namespace and derivation are public.

## Building

```sh
scripts/build-shim.sh          # builds libxuidforward.so, runs the smoke + parser tests
python -m pip wheel --no-deps -w build/wheel python_plugin   # builds the plugin wheel
```

Then drop `libxuidforward.so` and a matching `profile.json` into the plugin's data folder and
install the wheel into your Endstone environment.

## Status

Runs against BDS 1.26.51.1 (protocol 2193). Every BDS update needs a new profile before the hook
will install. No license is set yet — add one if you intend others to reuse it.
