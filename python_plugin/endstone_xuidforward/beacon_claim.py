"""xuidforward - checking a Beacon Proxy forwarding claim.

Beacon Proxy (https://github.com/ezchr/beacon-proxy) signs every login it sends a server with a
secret the server shares (forwarding.secret). The claim sits in the login's client data under
"BeaconForwarding"; the format is in Beacon's docs/forwarding.md. A login with a valid claim came
from Beacon, wherever Beacon runs, so its XUID can be trusted without the login having to come
from this machine.
"""

import base64
import hashlib
import hmac
import threading
import time

CLAIM_FIELD = "BeaconForwarding"


class ClaimVerifier:
    def __init__(self, secret: bytes, server: str = "", window_seconds: int = 60):
        self._secret = secret
        self._server = server
        self._window = max(int(window_seconds), 1)
        self._seen = {}
        self._lock = threading.Lock()

    def verify(self, claim, identity_public_key: str, xuid: str, name: str):
        """Returns (True, "") for a valid claim, else (False, reason)."""
        if not isinstance(claim, dict):
            return False, "no Beacon forwarding claim (the login did not come through Beacon)"
        if claim.get("v") != 1:
            return False, f"Beacon claim version {claim.get('v')!r} is not supported"
        if not identity_public_key:
            return False, "the login carries no public key to check the claim against"
        fields = [
            "beacon-forwarding-v1",
            str(claim.get("xuid", "")),
            str(claim.get("name", "")),
            str(claim.get("identity", "")),
            str(claim.get("ip", "")),
            str(claim.get("server", "")),
            str(int(claim.get("iat", 0) or 0)),
            str(claim.get("jti", "")),
            identity_public_key,
        ]
        expected = hmac.new(self._secret, "\n".join(fields).encode("utf-8"), hashlib.sha256).digest()
        try:
            got = base64.b64decode(str(claim.get("mac", "")), validate=True)
        except Exception:
            return False, "Beacon claim signature is not base64"
        if not hmac.compare_digest(expected, got):
            return False, "Beacon claim signature does not match: is forwarding.secret the same on both machines?"
        if self._server and claim.get("server") != self._server:
            return False, f"Beacon claim is for server {claim.get('server')!r}, not {self._server!r}"
        if str(claim.get("xuid")) != xuid or str(claim.get("name", "")).lower() != name.lower():
            return False, "Beacon claim names a different player than the login"
        now = time.time()
        age = now - int(claim.get("iat", 0) or 0)
        if abs(age) > self._window:
            return False, f"Beacon claim is {int(age)}s old: check both machines' clocks (NTP)"
        jti = str(claim.get("jti", ""))
        with self._lock:
            for old, seen in list(self._seen.items()):
                if now - seen > 2 * self._window:
                    del self._seen[old]
            if jti in self._seen:
                return False, "Beacon claim was already used"
            self._seen[jti] = now
        return True, ""


def read_secret(value: str, path: str) -> bytes:
    """The secret from the config: the value itself, or the contents of a file."""
    if value:
        return value.strip().encode("utf-8")
    if path:
        with open(path, "rb") as f:
            return f.read().strip()
    return b""
