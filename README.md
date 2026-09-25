# xuidforward

An [Endstone](https://github.com/EndstoneMC/endstone) plugin that makes a Bedrock Dedicated
Server keep the real XUID from a self-signed (offline) login, so players who reach the server
through a proxy get their own persistent player record instead of a fresh, empty one every join.

> **Built for BDS 1.26.51.1 (protocol 2193), Linux x86-64.** The native patch locates its site by
> signature, so it also installs on later builds that only shifted addresses; it refuses to patch
> if it can't find the site uniquely. See [Status](#status).

## The setup this is for

This plugin is only useful if you run a **proxy or relay in front of BDS** — something that
accepts a player's real Xbox Live connection, then opens its own login to BDS on the player's
behalf. That pattern is how projects bring Bedrock (or, via Geyser, Java) players onto a BDS world
through Xbox Live's Friends tab without every player connecting to BDS directly.

Because the proxy holds its own key and not the player's, the login it sends BDS is **self-signed**
(offline) rather than signed by Xbox Live — even though it carries the player's real XUID and name.
If you don't run a proxy like that, you don't need this plugin.

## The problem it solves

BDS drops the XUID of any login whose chain is self-signed (`AuthenticationType` 2) instead of
signed by Xbox Live. With `online-mode=false` it still lets the player in, but files them under a
**blank** XUID — so their inventory, position, stats and permissions reset on every reconnect. The
real XUID is right there in the login the proxy sends; BDS just discards it.

BDS is closed source and exposes no config option or script hook that runs before it resolves
identity, so a proxy in front of it cannot fix this on its own.

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

The native patch is **evidence-gated**: it carries a profile describing the patch site and refuses
to patch anything that does not match, so a bad match fails closed rather than corrupting a running
server. A profile names the site one of two ways:

- a **signature** — the site's opcodes with the build-specific relative operands wildcarded. At
  startup the plugin scans BDS's executable for it and patches only if it matches in **exactly one**
  place. Because it ignores the operands that a rebuild shifts, one profile keeps working across a
  BDS update until Mojang actually changes the instructions at the site. This is the default.
- a **fixed address** (`site_rva` + `expected_site_bytes`) — exact, but valid for one build only.

Profiles live in `plugin/profiles/`; `plugin/tools/verify.cpp` locates the site (by signature or
address) in a `bedrock_server` on disk without a running server, and `tools/elfscan.py` helps build
a profile for a new version.

## What it does and doesn't trust

The plugin never invents an XUID. It only ever copies the real one the proxy already put in the
login, and it guards that write so it can't be turned against a player:

- **Local origin only.** An identity is staged only for a login that arrives from this machine —
  i.e. from your proxy. A login coming straight off the network is never staged, and any pending
  stage is dropped the moment one arrives, so a direct connection can never pick up an identity
  meant for a proxied player.
- **Empty field only.** The hook fills the XUID only when BDS left it blank (which is exactly the
  self-signed case). A login that already carries a real Xbox XUID is never overwritten.
- **Verified name only.** Staging is keyed on the name from the login chain, never on a field the
  client writes for itself.
- **Short-lived, single-use.** Staged identities are consumed on use and expire in seconds.
- `SelfSignedId == uuid5(namespace, XUID)` is checked as a **consistency** signal, not
  authentication — the namespace and derivation are both public.

`online-mode=false` is required for BDS to accept the proxy's self-signed login, and that's fine:
this plugin does not weaken it. BDS still resolves a genuine Xbox login (for example someone
connecting directly) to that player's real XUID on its own, and the plugin leaves those untouched.
A modified client connecting directly can still pick any display name it likes — that's inherent
to `online-mode=false`, not something this plugin adds — but it gets no XUID, so it cannot inherit
another player's saved data or permissions, which BDS keys on the XUID.

## Installing

Two files end up on your server: the Python plugin wheel and the native `libxuidforward.so`.
Everything below runs on the Linux BDS machine — the `.so` is Linux x86-64 and can't be built or
run on Windows.

### Option A — prebuilt release (BDS 1.26.51.1 only)

The [latest release](../../releases/latest) has both files prebuilt, plus `INSTALL.txt` and
`SHA256SUMS`. If your BDS is exactly 1.26.51.1, Linux x86-64, use these — no compiler needed.

1. Put `endstone_xuidforward-<version>-py3-none-any.whl` into your server's `plugins/` folder
   (the same folder Endstone already loads plugins from).
2. Create `plugins/xuidforward/` and put `libxuidforward.so` inside it.
3. Restart BDS **fully** — not `/reload`; the native patch can't reinstall into a running server.

### Option B — build from source (any target, and the only way for a different BDS build)

```sh
scripts/build-shim.sh                                        # builds build/libxuidforward.so, runs the tests
python -m pip wheel --no-deps -w build/wheel python_plugin   # builds the plugin wheel
```

Needs `clang++-18` and libc++ dev headers. Then place the files and restart exactly as in steps
1–3 above. For a BDS build other than 1.26.51.1 you also need a matching profile: derive one (see
`plugin/tools/verify.cpp` and `tools/elfscan.py`), drop it into `plugins/xuidforward/` as
`profile.json`. For 1.26.51.1 the profile is built into the shim, so no `profile.json` is needed.

### Checking it worked

The BDS console on startup should show:

```
[Xuidforward] profile self-check: profile valid: BDS 1.26.51.1 (signature -> site 0x..., helper 0x...)
[Xuidforward] hook installed.
```

If instead it logs that the signature was not found or matched more than once, the login code in
your BDS build differs from what the profile targets — the hook stays off and BDS keeps its stock
behaviour until you supply an updated profile.

## Status

Built and validated against BDS 1.26.51.1 (protocol 2193). Thanks to signature location, a BDS
update that only shifts addresses should keep working with the shipped profile; you only need a new
profile if the plugin logs that the signature was not found (Mojang changed the login code) or
matched more than once. The struct field offsets are still version-specific — if those move, the
hook simply declines to write rather than writing to the wrong place, so it stays safe until the
profile's offsets are updated.

## License

MIT — see [LICENSE](LICENSE).
