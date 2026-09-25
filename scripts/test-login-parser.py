#!/usr/bin/env python3
"""Self-test for the login-body parser (fix #1).

Builds synthetic relay logins in each framing the parser claims to support - the
int32-little-endian blobs described in the review, the protocol's varuint32 blobs,
and a deliberately corrupted framing that must fall through to the scan - and
asserts the identity comes out of each.

This runs as part of the deploy gate: the previous parser was silently broken (it
ran json.loads over a binary packet body and looked for claims that live in a
different JWT), and the only symptom was that nothing was ever staged - which looks
identical to "the hook never fires". A test that fails loudly is the fix for that
class of bug, not just for this instance.
"""
import base64
import importlib.util
import json
import pathlib
import sys

# Load the parser by path: it has no Endstone dependency, so this test runs anywhere
# (the gate runs it on the server, this also runs on a plain workstation).
_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "python_plugin" / "endstone_xuidforward" / "login_body.py"
)
_spec = importlib.util.spec_from_file_location("xuidforward_login_body", _MODULE_PATH)
login_body = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(login_body)

is_self_signed = login_body.is_self_signed
names_for_staging = login_body.names_for_staging
parse_login_body = login_body.parse_login_body

XUID = "2535440792904888"
XNAME = "EzCrazy4395"
THIRD_PARTY_NAME = "EzCrazy4395"
SELF_SIGNED_ID = "0f0f0f0f-1111-2222-3333-444444444444"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(claims: dict) -> str:
    header = b64url(json.dumps({"alg": "ES384", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{b64url(b'signature')}"


def varuint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_body(inner: str, protocol: int = 2193) -> bytes:
    """A relay login body: the request JSON plus the client-data JWT."""
    token_a = jwt({"cpk": "PUBKEY", "identity": "IDENT", "xid": XUID, "xname": XNAME})
    client_data = jwt({"ThirdPartyName": THIRD_PARTY_NAME, "SelfSignedId": SELF_SIGNED_ID})
    request = json.dumps(
        {"Certificate": {"chain": [""]}, "AuthenticationType": 2, "Token": token_a}
    ).encode()

    if inner == "le":
        prefixed = lambda blob: len(blob).to_bytes(4, "little", signed=True) + blob  # noqa: E731
    else:
        prefixed = lambda blob: varuint(len(blob)) + blob  # noqa: E731

    blob = prefixed(request) + prefixed(client_data.encode())
    return protocol.to_bytes(4, "big") + varuint(len(blob)) + blob


def check(label: str, body: bytes) -> bool:
    parsed = parse_login_body(body)
    if not parsed:
        print(f"FAIL {label}: parser returned None for {len(body)} bytes")
        return False
    ok = (
        parsed["xuid"] == XUID
        and parsed["xname"] == XNAME
        and parsed["third_party_name"] == THIRD_PARTY_NAME
        and parsed["self_signed_id"] == SELF_SIGNED_ID
        and parsed["auth_type"] == 2
        and is_self_signed(parsed)
        and names_for_staging(parsed) == [XNAME]
    )
    print(
        f"{'PASS' if ok else 'FAIL'} {label}: framing={parsed['framing']} "
        f"protocol={parsed['protocol']} authType={parsed['auth_type']} xuid={parsed['xuid']!r} "
        f"xname={parsed['xname']!r} thirdPartyName={parsed['third_party_name']!r} "
        f"selfSignedId={parsed['self_signed_id']!r} names={names_for_staging(parsed)}"
    )
    return ok


def main() -> int:
    ok = True
    ok &= check("int32-le blobs", build_body("le"))
    ok &= check("varuint32 blobs", build_body("varuint"))

    # Corrupt the length prefix so both structured layouts fail: the scan must save it.
    body = build_body("le")
    corrupted = body[0:4] + b"\x00\x00" + body[6:]
    parsed = parse_login_body(corrupted)
    scan_ok = bool(parsed) and parsed["xuid"] == XUID and parsed["framing"] == "scan"
    print(f"{'PASS' if scan_ok else 'FAIL'} scan fallback: framing={parsed and parsed['framing']}")
    ok &= scan_ok

    # ThirdPartyName is client-written: a different value there must never become a staging key.
    mismatch = dict(parse_login_body(build_body("le")), third_party_name="SomeoneElse")
    only_verified = names_for_staging(mismatch) == [XNAME]
    print(f"{'PASS' if only_verified else 'FAIL'} only the verified name is staged: {names_for_staging(mismatch)}")
    ok &= only_verified

    # Garbage must be rejected, not guessed at.
    junk = parse_login_body(b"\x00" * 32) is None
    print(f"{'PASS' if junk else 'FAIL'} junk body is rejected")
    ok &= junk

    print("PARSER TEST PASSED" if ok else "PARSER TEST FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
