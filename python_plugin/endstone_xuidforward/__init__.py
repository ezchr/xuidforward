"""xuidforward - Endstone plugin side.

Stages the identity of relayed (self-signed) logins so the native shim can restore
the player's real XUID inside BDS's login path, before player storage is selected.

The packet handling lives here because PacketReceiveEvent is part of the public
Python API. The code patch cannot live here, so it is in libxuidforward.so, loaded
into this (BDS) process with ctypes.

SECURITY - READ THIS

`SelfSignedId == uuid5(namespace_uuid, XUID)` is a *consistency* check, NOT an
authentication control. Both the namespace and the derivation are public (see the
relay's proxy/self_signed_id.go), so anyone who can deliver a self-signed login can
claim an arbitrary XUID and compute the matching SelfSignedId. BDS accepts
self-signed chains (online-mode=false), and its own NetherNet session path makes the
login handler reachable by remote clients - so this check alone would let an attacker
have BDS load, and then overwrite, another player's save data.

An identity is therefore only staged when the login **arrives from this machine** - the
relay's signalling hop is loopback, but its NetherNet/ICE data connection shows up as one of the
host's own addresses (observed: <the box's own public address> with an ephemeral UDP port) - *and* its
claims are internally consistent. The real authentication boundary is the relay's Xbox Live
front door plus the fact that BDS's login handler is not reachable from outside; the source check
makes the plugin enforce that rather than assume it.

`SelfSignedId == uuid5(namespace_uuid, XUID)` is a *consistency* check, NOT an authentication
control. Both the namespace and the derivation are public (see the relay's
proxy/self_signed_id.go), so anyone who can deliver a self-signed login can compute a matching
value. It stays because it catches a relay whose persistence fix is off, or a login that did not
come from this relay - not because it proves anything.

Residual assumption: a *local* process could still reach the handler and forge a login. On a box
where that process would have to be root-equivalent to exist, that is accepted. If the relay ever
moves off this machine, replace the loopback rule with an explicit source allowlist (or a signed
single-use token).
"""

import ctypes
import json
import re
import socket
import subprocess
import time
from pathlib import Path

from endstone.command import Command, CommandSender
from endstone.event import PacketReceiveEvent, event_handler
from endstone.plugin import Plugin

from .login_body import is_self_signed, names_for_staging, parse_login_body

LOGIN_PACKET_ID = 0x01
DEFAULT_NAMESPACE = "a3e78ee7-823a-4cb5-9fe0-532b54ccc20d"

DEFAULT_CONFIG = {
    "_comment": "xuidforward - restore the real XUID on relayed (self-signed) logins. "
    "dry_run only logs what it would do; leave it on until a test join looks right.",
    "_security": "Two layers guard the write. (1) require_local_source: a login is only staged when "
    "it arrives from an address of this machine - the relay is local, and its NetherNet/ICE data "
    "connection shows up as one of the host's own addresses even though its signalling hop is "
    "loopback. auto_allow_local_addresses keeps that list current; allowed_sources adds explicit "
    "entries. This is the relay's own trust model ('only safe when the listener cannot be reached "
    "directly') made explicit. (2) require_self_signed_id_match is only a consistency check, NOT "
    "authentication: the namespace and the uuid5 derivation are public, so anyone who can reach the "
    "handler can satisfy it. Keep writes disabled (dry_run) until a relayed join shows the expected "
    "source and claims.",
    "enabled": True,
    "dry_run": True,
    "require_local_source": True,
    "auto_allow_local_addresses": True,
    "allowed_sources": ["127.0.0.1", "::1"],
    "namespace_uuid": DEFAULT_NAMESPACE,
    "require_self_signed_id_match": True,
    "require_digit_xuid": True,
    # The hook consumes a stage within milliseconds of the login packet; anything older
    # belongs to a login that failed, and must not wait around for another login.
    "stage_ttl_seconds": 5,
    "profile": "",
    "shim_path": "",
}


class XuidForward(Plugin):
    api_version = "0.11"

    commands = {
        "xuidforward": {
            "description": "xuidforward status and diagnostics.",
            "usages": ["/xuidforward status"],
            "permissions": ["xuidforward.command.status"],
        }
    }

    permissions = {
        "xuidforward.command.status": {
            "description": "Allow reading xuidforward's status.",
            "default": "op",
        }
    }

    def on_command(self, sender: CommandSender, command: Command, args) -> bool:
        if not args or str(args[0]).lower() != "status":
            sender.send_message("usage: /xuidforward status")
            return False
        sender.send_message(
            f"xuidforward: enabled={self._config['enabled']} dry_run={self._config['dry_run']} "
            f"hook={'installed' if self._hook_installed else 'NOT installed'} "
            f"shim={'loaded' if self._shim is not None else 'NOT loaded'}"
        )
        sender.send_message("accepted login sources: " + ", ".join(sorted(self._local_addresses)))
        if self._shim is not None:
            sender.send_message("counters: " + self._shim.xf_status().decode())
        return True

    def on_load(self) -> None:
        self._shim = None
        self._config = dict(DEFAULT_CONFIG)
        self._rejected_sources = 0
        self._last_reject_log = 0.0
        self._hook_installed = False
        self._load_config()
        self._local_addresses = self._detect_local_addresses()
        self._load_shim()

    def on_enable(self) -> None:
        self.register_events(self)
        if self._shim is None:
            self.logger.error("shim not loaded - no hook installed, logins are untouched")
            return
        if not self._config["enabled"]:
            self.logger.warning("disabled by configuration - no hook installed")
            return

        profile_path = self._config["profile"] or str(self.data_folder / "profile.json")
        if profile_path and not Path(profile_path).exists():
            self.logger.info(f"no profile at {profile_path} - using the shim's built-in profile")
            profile_path = ""
        profile = profile_path
        buffer = ctypes.create_string_buffer(512)
        rc = self._shim.xf_self_check(profile.encode(), buffer, len(buffer))
        self.logger.info(f"profile self-check: {buffer.value.decode()} (rc={rc})")
        if rc != 0:
            self.logger.error("profile does not match this BDS build - refusing to patch anything")
            return

        rc = self._shim.xf_install(
            profile.encode(),
            1 if self._config["dry_run"] else 0,
            str(self._config["namespace_uuid"]).encode(),
            int(self._config["stage_ttl_seconds"]),
            1 if self._config["require_self_signed_id_match"] else 0,
            1 if self._config["require_digit_xuid"] else 0,
        )
        if rc != 0:
            self.logger.error(f"hook not installed (rc={rc}): {self._shim.xf_last_error().decode()}")
            self.logger.error("this is the safe outcome - BDS keeps its stock behaviour")
            return

        self.logger.info(f"hook installed. {self._shim.xf_register_contract().decode()}")
        self._hook_installed = True
        self.logger.info(
            "accepted login sources: " + ", ".join(sorted(self._local_addresses))
            + " (the machine's own addresses; the relay's ICE data connection uses one of them)"
        )
        if self._config["dry_run"]:
            self.logger.warning(
                "DRY RUN - the hook is live and logs what it finds, but no XUID is written. "
                'Set "dry_run": false in config.json once a test join looks correct.'
            )
        else:
            self.logger.info("relayed logins will be rewritten to carry the player's real XUID")

    def on_disable(self) -> None:
        self._hook_installed = False
        if self._shim is not None:
            self._shim.xf_uninstall()
            self.logger.info("hook removed - BDS is back to stock behaviour")

    @event_handler
    def on_packet_receive(self, event: PacketReceiveEvent) -> None:
        if self._shim is None or not self._config["enabled"]:
            return
        if int(event.packet_id) != LOGIN_PACKET_ID:
            return

        # Where did this login come from? Only the relay on this box may hand us an
        # identity, so an unexpected source is rejected before anything else happens.
        try:
            source_host = (event.address.hostname or "").lower()
            source_port = int(event.address.port)
        except Exception:
            source_host, source_port = "", 0

        if not self._source_allowed(source_host):
            # BDS is about to process this login, and the hook matches staged identities by
            # name. Drop everything pending first, so a login from outside can never be handed
            # an identity staged for a relayed player - e.g. one whose join failed halfway.
            self._shim.xf_clear_stage()
            self._log_rejected_source(source_host, source_port, event.payload)
            return

        # The payload is the raw packet body (binary), not JSON - see login_body.py.
        parsed = parse_login_body(event.payload)
        if not parsed:
            self.logger.warning(
                f"login from {source_host}:{source_port}: could not parse the login body "
                f"({len(bytes(event.payload))} bytes) - nothing staged"
            )
            return

        xuid = parsed["xuid"]
        names = names_for_staging(parsed)
        self_id = parsed["self_signed_id"]

        # One line per login, so a dry run can never again look like "the hook never
        # fires" when the truth is that nothing was ever staged.
        self.logger.info(
            f"login parsed [{parsed['framing']}] from {source_host}:{source_port}: "
            f"authType={parsed['auth_type']} xname={parsed['xname']!r} "
            f"thirdPartyName={parsed['third_party_name']!r} xid={xuid!r} selfSignedId={self_id!r}"
        )

        if parsed["third_party_name"] and parsed["xname"] and (
            parsed["third_party_name"].lower() != parsed["xname"].lower()
        ):
            # ThirdPartyName is written by the client itself; only xname is staged, so this
            # cannot move an XUID, but a mismatch is worth seeing.
            self.logger.warning(
                f"login {parsed['xname']!r} claims a different ThirdPartyName "
                f"{parsed['third_party_name']!r} - staging under the verified name only"
            )

        if not self._hook_installed:
            self.logger.warning(
                "hook is not installed, so any XUID staged here would never be written - not staging"
            )
            return

        if parsed["auth_type"] is not None and not is_self_signed(parsed):
            self.logger.info(
                f"login {names[0] if names else '<unknown>'!r} is not a self-signed relay login "
                f"(authType={parsed['auth_type']}); BDS already has its real identity, not staging"
            )
            return

        if not xuid or not names:
            self.logger.warning(
                f"login from {source_host}:{source_port} carries no usable identity "
                f"(names={names} xuid={xuid!r}) - nothing staged"
            )
            return

        staged = []
        last_error = ""
        for name in names:
            rc = self._shim.xf_stage(name.encode(), xuid.encode(), str(self_id).encode())
            if rc == 0:
                staged.append(name)
            else:
                last_error = self._shim.xf_last_error().decode()

        if not staged:
            self.logger.warning(
                f"NOT staged: names={names} xuid={xuid}: {last_error or 'rejected by the shim'}"
            )
            return
        self.logger.info(
            f"staged: names={staged} xuid={xuid} selfSignedId={self_id} "
            f"from {source_host}:{source_port}"
        )

    # -- source guard -------------------------------------------------------

    def _detect_local_addresses(self) -> set:
        """Every address belonging to this machine (and loopback).

        The relay's *signalling* hop to BDS is loopback, but the NetherNet/ICE data
        connection it establishes can carry one of the host's own addresses as its
        source - in practice this server sees <the box's own public address> with an ephemeral
        UDP port. "Any address of this machine" is the rule that matches reality and
        still means what the guard needs: only a local process can be the source,
        since a remote peer cannot present our own address and complete a DTLS
        handshake.
        """
        addresses = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}
        try:
            output = subprocess.run(
                ["ip", "-o", "addr", "show"], capture_output=True, text=True, timeout=5
            ).stdout
            for token in re.findall(r"\binet6?\s+([0-9a-fA-F:.]+)/", output):
                addresses.add(token.lower())
        except Exception:
            pass
        # Fallback for a box without iproute2: ask the kernel which source address it
        # would use to reach the outside world.
        for family, target in ((socket.AF_INET, "1.1.1.1"), (socket.AF_INET6, "2606:4700:4700::1111")):
            probe = socket.socket(family, socket.SOCK_DGRAM)
            try:
                probe.connect((target, 53))
                addresses.add(str(probe.getsockname()[0]).lower())
            except OSError:
                pass
            finally:
                probe.close()
        return {address for address in addresses if address}

    def _source_allowed(self, host: str) -> bool:
        if not self._config.get("require_local_source", True):
            return True
        if not host:
            return False
        allowed = [str(entry).lower() for entry in self._config.get("allowed_sources", [])]
        if host in allowed:
            return True
        if self._config.get("auto_allow_local_addresses", True) and host in self._local_addresses:
            return True
        return host.startswith("127.") or host in ("::1", "localhost", "0:0:0:0:0:0:0:1")

    def _log_rejected_source(self, host: str, port: int, payload) -> None:
        # Rate limited: a login flood must not become a log flood.
        self._rejected_sources += 1
        now = time.monotonic()
        if now - self._last_reject_log < 30.0:
            return
        self._rejected_sources = 0
        self._last_reject_log = now

        # Log what the login *claimed* even though it is being ignored - it is only
        # read, never staged, and it makes an unexpected source self-explaining
        # (which names/claim values are reaching us, and from where).
        detail = ""
        try:
            parsed = parse_login_body(payload)
            if parsed:
                name = str(parsed["xname"] or parsed["third_party_name"])[:32]
                xuid = str(parsed["xuid"])[:24]
                detail = f" (claimed name={name!r} xuid={xuid!r} authType={parsed['auth_type']} - ignored)"
        except Exception:
            pass

        self.logger.warning(
            f"login from {host or '<unknown>'}:{port} rejected: not an address of this machine"
            f"{detail}; that login was left completely untouched"
        )

    # -- helpers ------------------------------------------------------------

    def _load_config(self) -> None:
        path = self.data_folder / "config.json"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
                return
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self._config.update({k: v for k, v in loaded.items() if not k.startswith("_")})
            # Keep the file in step with the defaults so an operator can see every knob,
            # without ever changing a value they set themselves.
            missing = [k for k in DEFAULT_CONFIG if not k.startswith("_") and k not in loaded]
            if missing:
                merged = {k: v for k, v in loaded.items()}
                for key in missing:
                    merged[key] = self._config[key]
                path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        except Exception as error:  # never let config problems stop the server
            self.logger.warning(f"could not read {path}: {error}; using defaults")

    def _load_shim(self) -> None:
        candidates = []
        if self._config.get("shim_path"):
            candidates.append(self._config["shim_path"])
        candidates += [
            str(self.data_folder / "libxuidforward.so"),
            str(self.data_folder.parent / "libxuidforward.so"),
            "/root/bedrock/plugins/xuidforward/libxuidforward.so",
            "/root/xuidfix/build/libxuidforward.so",
        ]
        for candidate in candidates:
            try:
                library = ctypes.CDLL(candidate)
            except OSError:
                continue
            if not hasattr(library, "xf_clear_stage"):
                # An older shim cannot drop pending identities when an outside login arrives;
                # installing the hook without that would reopen the hole it closes.
                self.logger.error(f"{candidate} is an older shim without xf_clear_stage - not using it")
                continue
            library.xf_clear_stage.restype = ctypes.c_int
            library.xf_version.restype = ctypes.c_char_p
            library.xf_last_error.restype = ctypes.c_char_p
            library.xf_register_contract.restype = ctypes.c_char_p
            library.xf_status.restype = ctypes.c_char_p
            library.xf_self_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            library.xf_install.argtypes = [
                ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int
            ]
            library.xf_stage.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            self._shim = library
            self.logger.info(f"shim loaded: {candidate} ({library.xf_version().decode()})")
            return
        self.logger.error("libxuidforward.so not found (looked in: " + ", ".join(candidates) + ")")
