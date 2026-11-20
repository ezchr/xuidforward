// xuidforward (Windows) - the hook profile loader, Windows edition.
//
// Same contract as the Linux profile.cpp (load a JSON profile, locate the site by its unique
// signature, refuse to patch anything that does not match), but the image is a PE: the base is
// the main module handle, executable segments come from the PE section table, and the on-disk
// size is the module file's size.
#include "profile.h"

#include <cstring>
#include <vector>

#include <windows.h>

#include "mini_json.h"
#include "signature.h"

namespace xuidforward {
namespace {

// Derived from BDS 1.26.65.1 windows-x86_64 (bedrock_server.exe, 232650056 bytes).
// Site: the PlayerAuthenticationInfo copy-constructor call inside
// ServerNetworkHandler::_processValidatedLoginPacket. The object it builds is the one BDS hands to
// player creation; its destination is in r14 across the call (result_register "r14").
constexpr const char *kSiteBytes =
    "E8 7B EC FF FF 90 48 8B 95 D0 06 00 00 4C 8D BD C0 04 00 00 C6 85 40 05 00 00 00 "
    "80 BA 80 00 00 00 01 75 10";

constexpr const char *kSiteSignature =
    "E8 ?? ?? ?? ?? 90 48 8B 95 D0 06 00 00 4C 8D BD C0 04 00 00 C6 85 40 05 00 00 00 "
    "80 BA 80 00 00 00 01 75 10";

struct ExecSpan {
    std::uintptr_t start;
    std::size_t length;
};

std::vector<ExecSpan> exec_segments(std::uintptr_t base)
{
    std::vector<ExecSpan> spans;
    const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return spans;
    }
    const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return spans;
    }
    const auto *section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        const std::size_t len = section->Misc.VirtualSize ? section->Misc.VirtualSize
                                                          : section->SizeOfRawData;
        if (len > 0) {
            spans.push_back({base + section->VirtualAddress, len});
        }
    }
    return spans;
}

}  // namespace

const Profile &builtin_profile()
{
    static const Profile profile = [] {
        Profile p;
        p.bds_version = "1.26.65.1";
        p.executable_size = 232650056;
        p.site_rva = 0xb89550;
        p.helper_rva = 0xb881d0;
        p.site_signature = kSiteSignature;
        parse_hex_bytes(kSiteBytes, p.expected_site_bytes);
        p.offsets = FieldOffsets{0, 192, 0, 32};  // xuid, xbox_live_name, engaged(unused, plain), sizeof
        p.result_register = "r14";
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
    const bool has_site_rva = values.find("site_rva") != values.end();
    const bool has_signature = values.find("site_signature") != values.end();
    if (has_site_rva && !has_signature) {
        profile.site_signature.clear();
    }
    if (has_signature && !has_site_rva) {
        profile.site_rva = 0;
        profile.helper_rva = 0;
    }
    if (const auto it = values.find("result_register"); it != values.end()) {
        if (it->second != "rbx" && it->second != "rdi" && it->second != "r14") {
            error = "result_register must be \"rbx\", \"rdi\" or \"r14\"";
            return std::nullopt;
        }
        profile.result_register = it->second;
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

    constexpr std::uint64_t kMaxStruct = 4096;
    if (profile.offsets.string_size < 16 || profile.offsets.string_size > 64) {
        error = "offset_string_size is not a plausible sizeof(std::string)";
        return std::nullopt;
    }
    if ((profile.offsets.xuid % 8) != 0 || (profile.offsets.xbox_live_name % 8) != 0) {
        error = "offset_xuid and offset_xbox_live_name must be 8-aligned (they hold std::strings)";
        return std::nullopt;
    }
    if (profile.offsets.xuid == profile.offsets.xbox_live_name) {
        error = "offset_xuid and offset_xbox_live_name must differ";
        return std::nullopt;
    }
    if (profile.offsets.engaged >= kMaxStruct ||
        profile.offsets.xuid + profile.offsets.string_size > kMaxStruct ||
        profile.offsets.xbox_live_name + profile.offsets.string_size > kMaxStruct) {
        error = "a profile offset is outside the plausible struct size - refusing it";
        return std::nullopt;
    }

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
        if (!verify_site(profile, base, error)) {
            return false;
        }
        if (profile.helper_rva == 0) {
            error = "profile has a fixed site_rva but no helper_rva";
            return false;
        }
        if (resolved_note != nullptr) {
            char b[48];
            std::snprintf(b, sizeof(b), "fixed site_rva 0x%llx",
                          static_cast<unsigned long long>(profile.site_rva));
            *resolved_note = b;
        }
        return true;
    }

    Signature sig;
    if (!parse_signature(profile.site_signature, sig)) {
        error = "site_signature is malformed";
        return false;
    }

    const auto spans = exec_segments(base);
    if (spans.empty()) {
        error = "could not find the BDS image's executable sections to scan";
        return false;
    }

    std::size_t total_matches = 0;
    std::uintptr_t match_addr = 0;
    for (const auto &span : spans) {
        std::size_t first = 0;
        const std::size_t n =
            signature_scan(reinterpret_cast<const std::uint8_t *>(span.start), span.length, sig, first);
        if (n > 0 && total_matches == 0) {
            match_addr = span.start + first;
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
        error = "bedrock_server.exe size is " + std::to_string(actual_size) + ", profile expects " +
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
    return reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
}

std::uint64_t main_image_size()
{
    wchar_t path[MAX_PATH * 2];
    const DWORD n = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (n == 0 || n >= std::size(path)) {
        return 0;
    }
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
        return 0;
    }
    return (static_cast<std::uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
}

}  // namespace xuidforward
