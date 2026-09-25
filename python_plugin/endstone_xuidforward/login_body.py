"""xuidforward - reading the identity out of a relaying login packet.

`PacketReceiveEvent.payload` is the raw packet *body* with the header stripped, so
it is binary - not JSON. For a Login packet, the relay's fork of gophertunnel's
`login.EncodeOffline` produces something shaped like:

    int32 BE      client protocol (e.g. 2193)
    varuint32     length of the connection-request blob
    <request>     JSON: {"Certificate":{"chain":[""]},"AuthenticationType":2,
                         "Token":"<JWT A>"}
    <client data> JWT B  (a second length-prefixed blob)

    JWT A (the "Token" claim of the request)   -> xid (XUID), xname (display name)
    JWT B (the client data)                    -> ThirdPartyName, SelfSignedId

An earlier revision ran `json.loads` over the whole body and looked for
`XUID`/`ThirdPartyName`/`SelfSignedId` inside JWT A. Both were wrong, and the
failure was silent: the parser returned None, no identity was ever staged and the
hook had nothing to write - which looks exactly like "the hook never fires".

The two blobs have been described with two different length prefixes (int32
little-endian, and the protocol's varuint32), so this parser tries both, accepts one
only when the first blob really looks like the request JSON, and reports which one
worked in `framing`. A real join's log line then settles the question with evidence
rather than a guess.
"""

import base64
import json

# Claim names, as they appear in the two JWTs.
XUID_CLAIM = "xid"
NAME_CLAIM = "xname"
THIRD_PARTY_NAME_CLAIM = "ThirdPartyName"
SELF_SIGNED_ID_CLAIM = "SelfSignedId"

# The relay logs into the backend with a self-signed (offline) chain.
AUTHENTICATION_TYPE_SELF_SIGNED = 2


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def jwt_claims(token) -> dict:
    """Decode the payload segment of a JWT.

    Never verifies a signature - we cannot, the signing key belongs to the relay.
    The values are only used after the shim has confirmed they are internally
    consistent with the relay's derivation of SelfSignedId.
    """
    if not isinstance(token, str) or token.count(".") < 1:
        return {}
    segment = token.split(".")[1]
    try:
        claims = json.loads(b64url_decode(segment))
    except Exception:
        return {}
    return claims if isinstance(claims, dict) else {}


def _read_varuint32(body: bytes, offset: int):
    value = 0
    shift = 0
    while offset < len(body) and shift <= 35:
        byte = body[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return None, offset


def _read_int32_le(body: bytes, offset: int):
    if offset + 4 > len(body):
        return None, offset
    return int.from_bytes(body[offset:offset + 4], "little", signed=True), offset + 4


def _read_blob(body: bytes, offset: int, framing: str):
    """Read one length-prefixed blob in the requested framing."""
    if framing == "varuint32":
        length, offset = _read_varuint32(body, offset)
    else:
        length, offset = _read_int32_le(body, offset)
    if length is None or length <= 0 or offset + length > len(body):
        return None, offset
    return body[offset:offset + length], offset + length


def _json_object_span(text: str, start: int = 0):
    """Span of the first balanced {...} at or after `start`, string-aware."""
    begin = text.find("{", start)
    if begin < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(begin, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return begin, index + 1
    return None


def _identity_from_blobs(request_blob, client_data) -> dict:
    identity = {
        "auth_type": None,
        "xuid": "",
        "xname": "",
        "third_party_name": "",
        "self_signed_id": "",
    }
    try:
        request = json.loads(request_blob.decode("utf-8", "replace")) if request_blob else {}
    except Exception:
        request = {}
    if isinstance(request, dict):
        auth_type = request.get("AuthenticationType")
        identity["auth_type"] = auth_type if isinstance(auth_type, int) else None
        token_claims = jwt_claims(request.get("Token"))
        identity["xuid"] = str(token_claims.get(XUID_CLAIM, "") or "")
        identity["xname"] = str(token_claims.get(NAME_CLAIM, "") or "")
        if not client_data:
            # Some encoders keep the client data inside the request JSON instead.
            client_data = request.get("RawToken")
    client_claims = jwt_claims(client_data)
    identity["third_party_name"] = str(client_claims.get(THIRD_PARTY_NAME_CLAIM, "") or "")
    identity["self_signed_id"] = str(client_claims.get(SELF_SIGNED_ID_CLAIM, "") or "")
    return identity


def parse_login_body(payload) -> dict | None:
    """Parse a Login packet body. Returns None only if nothing could be read at all.

    `framing` in the result says which layout matched, e.g.
    "be+varuint32+le-blobs", "be+varuint32+varuint32-blobs" or "scan".
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8", "replace")
    body = bytes(payload)
    result = {
        "framing": None,
        "protocol": None,
        "auth_type": None,
        "xuid": "",
        "xname": "",
        "third_party_name": "",
        "self_signed_id": "",
    }
    if len(body) < 6:
        return None

    protocol = int.from_bytes(body[0:4], "big")

    # The layouts differ only in how the blobs are length-prefixed, so try each in
    # turn; a layout is accepted only when the first blob really looks like the
    # request JSON.
    for inner in ("le", "varuint32"):
        size, after_size = _read_varuint32(body, 4)
        if size is None:
            continue
        request_blob, offset = _read_blob(body, after_size, inner)
        if request_blob is None or request_blob[:1] != b"{":
            continue
        client_blob, _ = _read_blob(body, offset, inner)
        identity = _identity_from_blobs(
            request_blob, client_blob.decode("utf-8", "replace") if client_blob else ""
        )
        result.update(identity)
        result["framing"] = f"be+varuint32+{inner}-blobs"
        result["protocol"] = protocol
        return result

    # Fallback: scan for the JSON request and then for the next JWT, so a framing
    # change cannot silently turn into "the hook never fires" again.
    text = body.decode("utf-8", "replace")
    span = _json_object_span(text)
    if span is None:
        return None
    request_blob = text[span[0]:span[1]].encode("utf-8")
    client_data = ""
    tail = text[span[1]:]
    index = tail.find("eyJ")
    if index >= 0:
        remainder = tail[index:]
        end = len(remainder)
        for position, char in enumerate(remainder):
            if char in '" \r\n\t,}\\)':
                end = position
                break
        client_data = remainder[:end]
    result.update(_identity_from_blobs(request_blob, client_data))
    result["framing"] = "scan"
    result["protocol"] = protocol
    return result


def is_self_signed(parsed: dict) -> bool:
    """True for a relay-shaped (offline) login."""
    return parsed.get("auth_type") == AUTHENTICATION_TYPE_SELF_SIGNED


def names_for_staging(parsed: dict) -> list:
    """The name to key a staged identity by: `xname` only.

    `xname` is the display name the relay took from the player's verified Xbox login.
    `ThirdPartyName` sits in the client data, which the joining client writes itself,
    so it is never used as a key: staging under it would let a client file its XUID
    under someone else's name, and every extra name staged is one more entry that can
    outlive its login. If BDS ever builds the auth result from a different name, the
    hook finds nothing staged, leaves the login untouched and logs the mismatch.
    """
    name = parsed.get("xname")
    return [name] if isinstance(name, str) and name else []
