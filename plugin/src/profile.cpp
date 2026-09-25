#include "profile.h"

#include <cstring>
#include <fstream>
#include <link.h>
#include <sys/stat.h>
#include <vector>

#include "mini_json.h"
#include "signature.h"

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

// The same site with the four build-specific relative operands (each rel32 of the two calls, the
// two jcc and the jmp) wildcarded, so it locates the site in a rebuilt binary where only those
// displacements moved. The surrounding opcodes and the stack displacements stay fixed, which keeps
// the match unique.
constexpr const char *kSiteSignature =
    "E8 ?? ?? ?? ?? 80 BC 24 80 00 00 00 00 0F 85 ?? ?? ?? ?? 48 8D 7C 24 40 "
    "E8 ?? ?? ?? ?? 80 BC 24 70 01 00 00 01 0F 85 ?? ?? ?? ?? E9 ?? ?? ?? ??";

// Executable PT_LOAD segments of the main image (the BDS binary), collected for a signature scan.
struct ExecSegments {
    std::uintptr_t base{0};
    std::vector<std::pair<std::uintptr_t, std::size_t>> spans;  // (start address, length)
};

int collect_exec_segments(struct dl_phdr_info *info, size_t, void *data)
{
    // The main executable is the object with an empty name; take only it.
    if (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') {
        return 0;
    }
    auto *out = static_cast<ExecSegments *>(data);
    out->base = static_cast<std::uintptr_t>(info->dlpi_addr);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto &ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X) != 0 && ph.p_filesz > 0) {
            out->spans.emplace_back(static_cast<std::uintptr_t>(info->dlpi_addr + ph.p_vaddr),
                                    static_cast<std::size_t>(ph.p_filesz));
        }
    }
    return 1;  // main object found; stop iterating
}

}  // namespace

const Profile &builtin_profile()
{
    static const Profile profile = [] {
        Profile p;
        p.bds_version = "1.26.51.1";
        p.executable_size = 256132752;
        p.site_rva = 143760217;  // 0x8919b59
        p.helper_rva = 143762096;  // 0x891a2b0
        p.site_signature = kSiteSignature;
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
    if (const auto it = values.find("site_signature"); it != values.end()) {
        Signature probe;
        if (!parse_signature(it->second, probe)) {
            error = "site_signature is malformed (need hex bytes and ?? wildcards, at least one fixed byte)";
            return std::nullopt;
        }
        profile.site_signature = it->second;
    }
    // A profile that overrides site_rva but not the signature (or vice-versa) must not silently
    // keep the built-in's mismatched other half - a file that pins one clears the inherited other.
    const bool has_site_rva = values.find("site_rva") != values.end();
    const bool has_signature = values.find("site_signature") != values.end();
    if (has_site_rva && !has_signature) {
        profile.site_signature.clear();
    }
    if (has_signature && !has_site_rva) {
        profile.site_rva = 0;
        profile.helper_rva = 0;
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
    const bool has_signature_way = !profile.site_signature.empty();
    const bool has_fixed_way = profile.site_rva != 0 && !profile.expected_site_bytes.empty();
    if (!has_signature_way && !has_fixed_way) {
        error = "profile names no site: give either site_signature, or site_rva + expected_site_bytes";
        return std::nullopt;
    }
    return profile;
}

bool resolve_site(Profile &profile, std::uintptr_t base, std::string &error, std::string *resolved_note)
{
    if (profile.site_signature.empty()) {
        // No signature: hold to the fixed address and its exact bytes.
        if (!verify_site(profile, base, error)) {
            return false;
        }
        if (profile.helper_rva == 0) {
            error = "profile has a fixed site_rva but no helper_rva";
            return false;
        }
        if (resolved_note != nullptr) {
            *resolved_note = "fixed site_rva 0x" + [] (std::uint64_t v) {
                char b[32]; std::snprintf(b, sizeof(b), "%llx", static_cast<unsigned long long>(v)); return std::string(b);
            }(profile.site_rva);
        }
        return true;
    }

    Signature sig;
    if (!parse_signature(profile.site_signature, sig)) {
        error = "site_signature is malformed";
        return false;
    }

    ExecSegments segs;
    segs.base = base;
    dl_iterate_phdr(&collect_exec_segments, &segs);
    if (segs.spans.empty()) {
        error = "could not find the BDS image's executable segments to scan";
        return false;
    }

    std::size_t total_matches = 0;
    std::uintptr_t match_addr = 0;
    for (const auto &[start, len] : segs.spans) {
        std::size_t first = 0;
        const std::size_t n = signature_scan(reinterpret_cast<const std::uint8_t *>(start), len, sig, first);
        if (n > 0 && total_matches == 0) {
            match_addr = start + first;
        }
        total_matches += n;
        if (total_matches > 1) {
            break;
        }
    }

    if (total_matches == 0) {
        error = "site signature not found - BDS most likely changed the login code (needs a new profile)";
        return false;
    }
    if (total_matches > 1) {
        error = "site signature matched more than once - too ambiguous to patch safely; pin site_rva instead";
        return false;
    }

    profile.site_rva = static_cast<std::uint64_t>(match_addr - base);
    // The site's own `call rel32` names the helper we re-issue; derive it rather than trusting a
    // stored helper_rva that a rebuild would have moved.
    if (sig.fixed.empty() || !sig.fixed[0] || sig.bytes[0] != 0xE8) {
        error = "site signature does not begin with the call opcode - cannot derive the helper";
        return false;
    }
    std::int32_t rel = 0;
    std::memcpy(&rel, reinterpret_cast<const void *>(match_addr + 1), sizeof(rel));
    profile.helper_rva = static_cast<std::uint64_t>(static_cast<std::int64_t>(profile.site_rva + 5) + rel);

    if (resolved_note != nullptr) {
        char b[96];
        std::snprintf(b, sizeof(b), "signature -> site 0x%llx, helper 0x%llx",
                      static_cast<unsigned long long>(profile.site_rva),
                      static_cast<unsigned long long>(profile.helper_rva));
        *resolved_note = b;
    }
    return true;
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
