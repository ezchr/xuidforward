// xuidforward-verify - check a hook profile against a bedrock_server binary.
//
// This is the offline half of the plugin's safety model, and it needs neither
// Endstone nor a running server, so a profile can be validated (or re-derived
// after a BDS update) on any machine with a C++ compiler.
//
//   xuidforward-verify <bedrock_server> [profile.json] [--dump-relay out.bin]
//
// It answers exactly three questions:
//   1. are the profile's bytes present at the profile's site, in this binary?
//   2. does the site's call target look like the helper the relay re-issues?
//   3. does the relay machine code build cleanly, and what does it look like?
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "../src/hook.h"
#include "../src/profile.h"
#include "../src/signature.h"

namespace {

struct Image {
    std::vector<std::uint8_t> data;

    // Scan the executable PT_LOAD segments for a signature, the same way the plugin scans the
    // loaded image at runtime. Returns the number of matches and, via first_rva, the RVA of the
    // first - a caller wanting to patch requires exactly one.
    std::size_t scan_signature(const xuidforward::Signature &sig, std::uint64_t &first_rva) const
    {
        first_rva = 0;
        if (data.size() < sizeof(Elf64_Ehdr)) {
            return 0;
        }
        const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data.data());
        std::size_t total = 0;
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            const auto *phdr = reinterpret_cast<const Elf64_Phdr *>(
                data.data() + ehdr->e_phoff + static_cast<std::size_t>(i) * ehdr->e_phentsize);
            if (phdr->p_type != PT_LOAD || (phdr->p_flags & PF_X) == 0 || phdr->p_filesz == 0) {
                continue;
            }
            if (phdr->p_offset + phdr->p_filesz > data.size()) {
                continue;
            }
            std::size_t first = 0;
            const std::size_t n = xuidforward::signature_scan(
                data.data() + phdr->p_offset, static_cast<std::size_t>(phdr->p_filesz), sig, first);
            if (n > 0 && total == 0) {
                first_rva = phdr->p_vaddr + first;
            }
            total += n;
            if (total > 1) {
                break;
            }
        }
        return total;
    }

    // Map an RVA (what the profile stores) to a file offset using the ELF
    // program headers - the same mapping tools/elfscan.py performs.
    std::optional<std::uint64_t> offset_of(std::uint64_t rva) const
    {
        if (data.size() < sizeof(Elf64_Ehdr)) {
            return std::nullopt;
        }
        const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data.data());
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            const auto *phdr = reinterpret_cast<const Elf64_Phdr *>(
                data.data() + ehdr->e_phoff + static_cast<std::size_t>(i) * ehdr->e_phentsize);
            if (phdr->p_type != PT_LOAD) {
                continue;
            }
            if (rva >= phdr->p_vaddr && rva < phdr->p_vaddr + phdr->p_filesz) {
                return phdr->p_offset + (rva - phdr->p_vaddr);
            }
        }
        return std::nullopt;
    }

    const std::uint8_t *at(std::uint64_t rva) const
    {
        const auto offset = offset_of(rva);
        if (!offset || *offset >= data.size()) {
            return nullptr;
        }
        return data.data() + *offset;
    }
};

std::string hex(const std::uint8_t *bytes, std::size_t count)
{
    std::string out;
    char buffer[4];
    for (std::size_t i = 0; i < count; ++i) {
        std::snprintf(buffer, sizeof(buffer), "%02X ", bytes[i]);
        out += buffer;
    }
    if (!out.empty()) {
        out.pop_back();
    }
    return out;
}

}  // namespace

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cerr << "usage: xuidforward-verify <bedrock_server> [profile.json] [--dump-relay out.bin]\n";
        return 2;
    }
    const std::string binary_path = argv[1];
    std::string profile_path;
    std::string dump_path;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--dump-relay") == 0 && i + 1 < argc) {
            dump_path = argv[++i];
        }
        else if (profile_path.empty()) {
            profile_path = argv[i];
        }
    }

    std::ifstream file(binary_path, std::ios::binary);
    if (!file) {
        std::cerr << "cannot open " << binary_path << "\n";
        return 2;
    }
    Image image;
    image.data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    std::cout << "binary        : " << binary_path << "\n"
              << "size          : " << image.data.size() << " bytes\n";

    xuidforward::Profile profile = xuidforward::builtin_profile();
    if (!profile_path.empty()) {
        std::string error;
        const auto loaded = xuidforward::load_profile(profile_path, error);
        if (!loaded) {
            std::cerr << "profile error : " << error << "\n";
            return 1;
        }
        profile = *loaded;
        std::cout << "profile       : " << profile_path << "\n";
    }
    else {
        std::cout << "profile       : built-in (" << profile.bds_version << ")\n";
    }

    bool ok = true;

    // If the profile carries a signature, locate the site by pattern the way the plugin does at
    // runtime, and report it. This is what lets a profile outlive a BDS update that only shifts
    // addresses, so it's checked first and drives the site_rva used below.
    if (!profile.site_signature.empty()) {
        xuidforward::Signature sig;
        if (!xuidforward::parse_signature(profile.site_signature, sig)) {
            std::cout << "signature     : MALFORMED\n";
            ok = false;
        }
        else {
            std::uint64_t found_rva = 0;
            const std::size_t n = image.scan_signature(sig, found_rva);
            if (n == 1) {
                std::int32_t disp = 0;
                std::memcpy(&disp, image.at(found_rva) + 1, sizeof(disp));
                const auto helper = static_cast<std::uint64_t>(static_cast<std::int64_t>(found_rva + 5) + disp);
                std::cout << "signature     : unique match at rva " << found_rva
                          << " (helper " << helper << ")\n";
                if (profile.site_rva != 0 && profile.site_rva != found_rva) {
                    std::cout << "  note        : differs from profile site_rva " << profile.site_rva << "\n";
                }
                profile.site_rva = found_rva;
                profile.helper_rva = helper;
            }
            else {
                std::cout << "signature     : " << (n == 0 ? "NOT FOUND" : "AMBIGUOUS (>1 match)") << "\n";
                ok = false;
            }
        }
    }

    if (profile.executable_size != 0 && profile.executable_size != image.data.size()) {
        std::cout << "size match    : NO (profile says " << profile.executable_size << ")\n";
        ok = false;
    }
    else {
        std::cout << "size match    : yes\n";
    }

    const std::uint8_t *site = image.at(profile.site_rva);
    if (site == nullptr) {
        std::cout << "site rva      : " << profile.site_rva << " is not mapped - profile is wrong\n";
        return 1;
    }
    const bool site_ok =
        std::memcmp(site, profile.expected_site_bytes.data(), profile.expected_site_bytes.size()) == 0;
    std::cout << "site rva      : " << profile.site_rva << "\n"
              << "site bytes    : " << (site_ok ? "match" : "MISMATCH") << "\n"
              << "  expected    : "
              << hex(reinterpret_cast<const std::uint8_t *>(profile.expected_site_bytes.data()),
                     profile.expected_site_bytes.size())
              << "\n"
              << "  found       : " << hex(site, profile.expected_site_bytes.size()) << "\n";
    ok = ok && site_ok;

    std::int32_t displacement = 0;
    std::memcpy(&displacement, site + 1, sizeof(displacement));
    const auto actual_target = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(profile.site_rva + 5) + displacement);
    std::cout << "call target   : " << actual_target << " (profile helper " << profile.helper_rva << ")"
              << (actual_target == profile.helper_rva ? " - match" : " - MISMATCH") << "\n";
    ok = ok && actual_target == profile.helper_rva;

    if (const std::uint8_t *helper = image.at(profile.helper_rva); helper != nullptr) {
        std::cout << "helper bytes  : " << hex(helper, 16) << "\n";
    }

    // Build the relay exactly as the plugin would, with placeholder addresses.
    const auto relay = xuidforward::build_relay(profile.helper_rva, 0x10000000);
    std::cout << "relay size    : " << relay.size() << " bytes\n"
              << "relay head    : " << hex(relay.data(), 32) << "\n"
              << "relay tail    : " << hex(relay.data() + relay.size() - 16, 16) << "\n";

    if (!dump_path.empty()) {
        std::ofstream out(dump_path, std::ios::binary);
        out.write(reinterpret_cast<const char *>(relay.data()), static_cast<std::streamsize>(relay.size()));
        std::cout << "relay dumped  : " << dump_path << "\n";
    }

    std::cout << (ok ? "RESULT        : profile is valid for this binary\n"
                     : "RESULT        : profile does NOT match this binary (plugin would refuse to hook)\n");
    return ok ? 0 : 1;
}
