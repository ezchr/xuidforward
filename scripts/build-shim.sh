#!/usr/bin/env bash
# Build the native shim (libxuidforward.so) and the Python plugin wheel.
#
# The shim needs no Endstone headers: it only touches the BDS image. It *is* built
# with libc++ because the one thing it manipulates in the guest process is a
# std::string, and libc++ is what BDS uses.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$HERE/build}"
PY="${PY:-/root/endstone_venv/bin/python}"
CXX="${CXX:-clang++-18}"

mkdir -p "$OUT"

echo "=== building libxuidforward.so ==="
"$CXX" -std=c++20 -O2 -fPIC -shared -stdlib=libc++ \
    -Wall -Wextra \
    -I"$HERE/plugin/src" \
    "$HERE/shim/xf_api.cpp" \
    "$HERE/plugin/src/profile.cpp" \
    "$HERE/plugin/src/hook.cpp" \
    "$HERE/plugin/src/inject.cpp" \
    "$HERE/plugin/src/stage.cpp" \
    -o "$OUT/libxuidforward.so"
ls -la "$OUT/libxuidforward.so"
echo "--- exported symbols ---"
nm -D --defined-only "$OUT/libxuidforward.so" | grep -E ' T xf_' || true

echo
echo "=== smoke test: load the shim in Python and self-check the profile ==="
"$PY" - "$OUT/libxuidforward.so" "$HERE/plugin/profiles/1.26.51.1-linux-x86_64.json" <<'PYEOF'
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
lib.xf_version.restype = ctypes.c_char_p
print("version  :", lib.xf_version().decode())
lib.xf_self_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
lib.xf_self_check.restype = ctypes.c_int
buf = ctypes.create_string_buffer(512)

# Layout detection first: this is the step that segfaulted the server in the first
# build, so it is exercised here, standalone, before anything gets deployed.
lib.xf_layout_probe.argtypes = [ctypes.c_char_p, ctypes.c_int]
lib.xf_layout_probe.restype = ctypes.c_int
rc_layout = lib.xf_layout_probe(buf, len(buf))
print("layout   :", rc_layout, buf.value.decode())
if rc_layout != 0:
    print("!! layout detection failed - the plugin would refuse to patch (safe, but useless)")
    sys.exit(1)

rc = lib.xf_self_check(sys.argv[2].encode(), buf, len(buf))
print("selfcheck:", rc, buf.value.decode())
lib.xf_register_contract.restype = ctypes.c_char_p
print("contract :", lib.xf_register_contract().decode())

# Staging logic, including the uuid5 binding check, can also be tested here.
import uuid
ns_text = "a3e78ee7-823a-4cb5-9fe0-532b54ccc20d"
lib.xf_set_namespace.argtypes = [ctypes.c_char_p]
lib.xf_status.restype = ctypes.c_char_p
lib.xf_stage.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.xf_set_namespace(ns_text.encode())
xuid = "2535451513084498"
good = str(uuid.uuid5(uuid.UUID(ns_text), xuid)).encode()
bad = lib.xf_stage(b"testplayer", xuid.encode(), b"00000000-0000-0000-0000-000000000000")
ok_pos = lib.xf_stage(b"testplayer", xuid.encode(), good)
print("stage(bad) :", bad, "(must be non-zero: rejected)")
print("stage(good):", ok_pos, "(must be 0: accepted)")
print("status     :", lib.xf_status().decode())

# The gate: layout detection must work, a wrong SelfSignedId must be rejected, and a
# correct one must be accepted. The profile self-check legitimately fails outside a
# running server (no BDS image), so it does not gate the build.
if rc_layout != 0 or bad == 0 or ok_pos != 0:
    print("!! SMOKE TEST FAILED")
    sys.exit(1)
print("SMOKE TEST PASSED")
sys.exit(0)
PYEOF

echo
echo "=== login parser self-test (fix #1) ==="
"$PY" "$HERE/scripts/test-login-parser.py" || {
    echo "!! login parser self-test failed - refusing to continue"
    exit 1
}

echo
echo "=== building the Python plugin wheel ==="
cd "$HERE/python_plugin"
"$PY" -m pip wheel --no-deps -w "$OUT/wheel" . >/dev/null 2>&1 || {
    echo "!! wheel build failed - building it is optional, an editable install works too"
}
ls -la "$OUT/wheel" 2>/dev/null || true
echo "SHIM_BUILD_OK"
