#include "profile.h"

#include <cstring>
#include <fstream>
#include <link.h>
#include <sys/stat.h>

#include "mini_json.h"

namespace xuidforward {
namespace {

// Derived from BDS 1.26.51.1 linux-x86_64 (bedrock_server, 256132752 bytes).
// Site: the `call` inside ServerNetworkHandler::_validateLoginPacket that builds
// the PlayerAuthenticationInfo result. Byte-for-byte the same code as the
// OniLink-validated 1.26.45.1 profile apart from the two call displacements -
// see README.md "How the profile was derived" for the evidence trail.
constexpr const char *kSiteBytes =
    "E8 52 07 00 00 80 BC 24 80 00 00 00 00 0F 85 0C FF FF FF 48 8D 7C 24 40 "
    "E8 6A D1 EC FB 80 BC 24 70 01 00 00 01 0F 85 BD FB FF FF E9 FD FE FF FF";

}  // namespace

const Profile &builtin_profile()
{
    static const Profile profile = [] {
        Profile p;
        p.bds_version = "1.26.51.1";
        p.executable_size = 256132752;
        p.site_rva = 143760217;  // 0x8919b59
        p.helper_rva = 143762096;  // 0x891a2b0
        parse_hex_bytes(kSiteBytes, p.expected_site_bytes);
        p.offsets = FieldOffsets{0, 144, 296, 24};
        return p;
    }();
    return profile;
}

std::optional<Profile> load_profile(const std::string &path, std::string &error)
{
    std::string text;
    if (!read_file(path, text)) {
        error = "cannot read profile " + path;
        return std::nullopt;
    }
    const auto values = parse_flat_json(text);
    if (values.empty()) {
        error = "profile " + path + " is empty or not a flat JSON object";
        return std::nullopt;
    }
    Profile profile = builtin_profile();
    if (const auto it = values.find("bds_version"); it != values.end()) {
        profile.bds_version = it->second;
    }
    if (const auto it = values.find("executable_size"); it != values.end()) {
        if (const auto v = parse_u64(it->second)) {
            profile.executable_size = *v;
        }
    }
    if (const auto it = values.find("site_rva"); it != values.end()) {
        if (const auto v = parse_u64(it->second)) {
            profile.site_rva = *v;
        }
    }
    if (const auto it = values.find("helper_rva"); it != values.end()) {
        if (const auto v = parse_u64(it->second)) {
            profile.helper_rva = *v;
        }
    }
    if (const auto it = values.find("expected_site_bytes"); it != values.end()) {
        std::string bytes;
        if (!parse_hex_bytes(it->second, bytes)) {
            error = "expected_site_bytes is malformed";
            return std::nullopt;
        }
        profile.expected_site_bytes = bytes;
    }
    const auto offset_of = [&](const char *key, std::uint64_t fallback) {
        if (const auto it = values.find(key); it != values.end()) {
            if (const auto v = parse_u64(it->second)) {
                return static_cast<std::uint64_t>(*v);
            }
        }
        return fallback;
    };
    profile.offsets.xuid = offset_of("offset_xuid", profile.offsets.xuid);
    profile.offsets.xbox_live_name = offset_of("offset_xbox_live_name", profile.offsets.xbox_live_name);
    profile.offsets.engaged = offset_of("offset_engaged", profile.offsets.engaged);
    profile.offsets.string_size = offset_of("offset_string_size", profile.offsets.string_size);
    if (profile.site_rva == 0 || profile.helper_rva == 0 || profile.expected_site_bytes.empty()) {
        error = "profile is missing site_rva, helper_rva or expected_site_bytes";
        return std::nullopt;
    }
    return profile;
}

bool verify_site(const Profile &profile, std::uintptr_t base, std::string &error)
{
    const auto actual_size = main_image_size();
    if (profile.executable_size != 0 && actual_size != 0 && actual_size != profile.executable_size) {
        error = "bedrock_server size is " + std::to_string(actual_size) + ", profile expects " +
                std::to_string(profile.executable_size) + " - BDS was probably updated";
        return false;
    }
    const auto *site = reinterpret_cast<const unsigned char *>(base + profile.site_rva);
    if (std::memcmp(site, profile.expected_site_bytes.data(), profile.expected_site_bytes.size()) != 0) {
        std::string got;
        for (std::size_t i = 0; i < profile.expected_site_bytes.size(); ++i) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02X ", site[i]);
            got += buf;
        }
        error = "site bytes at " + std::to_string(profile.site_rva) + " do not match the profile; got " + got;
        return false;
    }
    return true;
}

std::uintptr_t main_image_base()
{
    std::uintptr_t base = 0;
    dl_iterate_phdr(
        [](struct dl_phdr_info *info, size_t, void *data) {
            // The main executable is the object with an empty name.
            if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
                *static_cast<std::uintptr_t *>(data) = static_cast<std::uintptr_t>(info->dlpi_addr);
                return 1;
            }
            return 0;
        },
        &base);
    return base;
}

std::uint64_t main_image_size()
{
    const std::string path = "/proc/self/exe";
    struct stat info {};
    if (stat(path.c_str(), &info) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(info.st_size);
}

}  // namespace xuidforward
