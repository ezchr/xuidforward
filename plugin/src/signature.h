// xuidforward - byte-signature matching for locating the hook site.
//
// A profile can name the hook site two ways: a fixed site_rva (exact, but only
// valid for one build) or a signature - the site's opcodes with the
// build-specific relative operands wildcarded. The signature survives a BDS
// update that only shifts addresses, so the same profile keeps working until
// Mojang actually changes the instructions there.
//
// Format: space-separated hex bytes, "??" for a wildcard, e.g.
//   "E8 ?? ?? ?? ?? 80 BC 24 80 00 00 00 00 0F 85 ?? ?? ?? ??"
// Safety rests on the match being UNIQUE across the scanned range; a caller that
// finds zero or several matches must refuse to patch.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace xuidforward {

struct Signature {
    std::vector<std::uint8_t> bytes;  // value at fixed positions, 0 where wildcarded
    std::vector<bool> fixed;          // true = this position must match

    [[nodiscard]] std::size_t size() const { return bytes.size(); }
    [[nodiscard]] bool empty() const { return bytes.empty(); }

    [[nodiscard]] bool matches_at(const std::uint8_t *p) const
    {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (fixed[i] && p[i] != bytes[i]) {
                return false;
            }
        }
        return true;
    }
};

// Parse "AA ?? BB" into a Signature. Returns false on any malformed token or if
// the pattern has no fixed byte to anchor on.
inline bool parse_signature(const std::string &text, Signature &out)
{
    out = Signature{};
    const auto hex_nibble = [](char c, int &v) {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };
    std::size_t i = 0;
    bool any_fixed = false;
    while (i < text.size()) {
        if (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' || text[i] == '\n') {
            ++i;
            continue;
        }
        const char a = text[i];
        const char b = i + 1 < text.size() ? text[i + 1] : '\0';
        if (a == '?' && b == '?') {
            out.bytes.push_back(0);
            out.fixed.push_back(false);
            i += 2;
        }
        else {
            int hi = 0, lo = 0;
            if (!hex_nibble(a, hi) || !hex_nibble(b, lo)) {
                out = Signature{};
                return false;
            }
            out.bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
            out.fixed.push_back(true);
            any_fixed = true;
            i += 2;
        }
    }
    return !out.bytes.empty() && any_fixed;
}

// Scan [begin, begin+length) for the signature. Sets first_index to the offset
// of the first match and returns the total number of matches (a caller wanting
// safety requires exactly 1). Anchors on the first fixed byte so the scan of a
// multi-megabyte code segment stays quick.
inline std::size_t signature_scan(const std::uint8_t *begin, std::size_t length, const Signature &sig,
                                  std::size_t &first_index)
{
    first_index = 0;
    if (sig.empty() || length < sig.size()) {
        return 0;
    }
    std::size_t anchor = 0;
    while (anchor < sig.size() && !sig.fixed[anchor]) {
        ++anchor;
    }
    const std::uint8_t anchor_byte = sig.bytes[anchor];
    const std::size_t last = length - sig.size();
    std::size_t count = 0;
    for (std::size_t i = 0; i <= last; ++i) {
        if (begin[i + anchor] != anchor_byte) {
            continue;
        }
        if (sig.matches_at(begin + i)) {
            if (count == 0) {
                first_index = i;
            }
            if (++count > 1) {
                return count;  // ambiguous - caller only needs to know it is >1
            }
        }
    }
    return count;
}

}  // namespace xuidforward
