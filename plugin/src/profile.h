// xuidforward - the hook profile: which bytes in which BDS build to hook.
//
// A profile is evidence, not configuration. It records the exact call site the
// injection rides on (with its preceding bytes), the helper that site calls, the
// struct offsets involved, and the executable size it was derived from. The
// plugin refuses to patch anything unless the running BDS image matches: a BDS
// update changes these numbers, and silently hooking the wrong address would
// corrupt or crash the server.
//
// Profiles are produced by tools/elfscan.py (see README.md for the derivation).
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace xuidforward {

// Layout of BDS's PlayerAuthenticationInfo, as consumed by
// ServerNetworkHandler::_createNewPlayer. Offsets are validated at runtime
// before anything is written (see inject.cpp).
struct FieldOffsets {
    std::uint64_t xuid{0};              // std::string, compared for storage ids
    std::uint64_t xbox_live_name{144};  // std::string, used to match staged logins
    std::uint64_t engaged{296};         // optional<PlayerAuthenticationInfo>::engaged
    std::uint64_t string_size{24};      // sizeof(std::string) in this ABI
};

struct Profile {
    std::string bds_version;           // informational
    std::uint64_t executable_size{0};  // byte size of bedrock_server this was derived from
    std::uint64_t site_rva{0};         // the `call` we replace (0 = locate via site_signature)
    std::string expected_site_bytes;   // raw bytes that must be present at site_rva (legacy exact match)
    std::uint64_t helper_rva{0};       // call target we re-issue (0 = derive from the call at the site)
    // site_signature, when set, locates the site by pattern instead of a fixed address: the site's
    // opcodes with the build-specific relative operands wildcarded ("E8 ?? ?? ?? ?? ..."). It must
    // match in exactly one place or the plugin refuses to patch. This lets one profile survive a
    // BDS update that only shifts addresses. See resolve_site and signature.h.
    std::string site_signature;
    FieldOffsets offsets;
};

// Load a profile JSON file. Returns std::nullopt and fills `error` on failure.
std::optional<Profile> load_profile(const std::string &path, std::string &error);

// The built-in profile for BDS 1.26.51.1 linux-x86_64 (the build this was
// derived and validated against). Used when no profile file is configured.
const Profile &builtin_profile();

// Verify that a loaded image matches the profile: same executable size and the
// expected bytes at the site. Fills `error` and returns false on any mismatch.
bool verify_site(const Profile &profile, std::uintptr_t base, std::string &error);

// Pin the profile's site to a concrete address in the loaded image. For a profile that carries a
// site_signature this scans the executable segments for the (unique) match, sets site_rva, and,
// when helper_rva is 0, derives it from the relative call at the site. For a profile with no
// signature it falls back to verify_site (the fixed-address exact-bytes check). Fills `error` and
// returns false - patching nothing - if the signature is missing, absent, or matches more than
// once. `resolved_note` (optional) receives a short human-readable account of what was located.
bool resolve_site(Profile &profile, std::uintptr_t base, std::string &error,
                  std::string *resolved_note = nullptr);

// Base address of the main executable (the BDS image) in this process.
std::uintptr_t main_image_base();

// Size of the main executable on disk, 0 if it cannot be determined.
std::uint64_t main_image_size();

}  // namespace xuidforward
