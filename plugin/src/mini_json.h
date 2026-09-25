// xuidforward - minimal flat-JSON reader.
//
// The plugin only ever parses two things: its own config file and the small
// hook-profile file next to it. Both are flat objects of string/number/bool
// values, so a full JSON library would be dead weight (and one more dependency
// to build against). This parser handles exactly that shape and nothing else:
// nested objects/arrays are skipped, not interpreted.
#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

namespace xuidforward {

inline std::string trim(const std::string &s)
{
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

inline std::string unquote(const std::string &s)
{
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
            case 'n': out.push_back('\n'); break;
            case 't': out.push_back('\t'); break;
            case 'r': out.push_back('\r'); break;
            default: out.push_back(s[i]); break;
            }
        }
        else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// Parse a flat JSON object into key -> value (strings already unquoted).
inline std::unordered_map<std::string, std::string> parse_flat_json(const std::string &text)
{
    std::unordered_map<std::string, std::string> values;
    std::size_t i = 0;
    const std::size_t n = text.size();
    while (i < n) {
        const auto quote = text.find('"', i);
        if (quote == std::string::npos) {
            break;
        }
        std::string key;
        for (std::size_t j = quote + 1; j < n; ++j) {
            if (text[j] == '\\' && j + 1 < n) {
                key.push_back(text[j]);
                key.push_back(text[++j]);
                continue;
            }
            if (text[j] == '"') {
                i = j + 1;
                break;
            }
            key.push_back(text[j]);
        }
        key = unquote(key);

        const auto colon = text.find(':', i);
        if (colon == std::string::npos) {
            break;
        }
        std::size_t value_start = colon + 1;
        while (value_start < n && (text[value_start] == ' ' || text[value_start] == '\t' ||
                                  text[value_start] == '\r' || text[value_start] == '\n')) {
            ++value_start;
        }
        if (value_start >= n) {
            break;
        }

        std::string value;
        if (text[value_start] == '"') {
            std::string raw;
            for (std::size_t j = value_start + 1; j < n; ++j) {
                if (text[j] == '\\' && j + 1 < n) {
                    raw.push_back(text[j]);
                    raw.push_back(text[++j]);
                    continue;
                }
                if (text[j] == '"') {
                    i = j + 1;
                    break;
                }
                raw.push_back(text[j]);
            }
            value = unquote(raw);
        }
        else if (text[value_start] == '{' || text[value_start] == '[') {
            int depth = 0;  // nested container: skip it wholesale
            for (std::size_t j = value_start; j < n; ++j) {
                if (text[j] == '{' || text[j] == '[') {
                    ++depth;
                }
                else if (text[j] == '}' || text[j] == ']') {
                    if (--depth == 0) {
                        i = j + 1;
                        break;
                    }
                }
            }
            continue;
        }
        else {
            const auto end = text.find_first_of(",}\r\n", value_start);
            value = trim(text.substr(value_start, end == std::string::npos ? end : end - value_start));
            i = end == std::string::npos ? n : end + 1;
        }
        if (!key.empty()) {
            values[key] = value;
        }
    }
    return values;
}

inline bool read_file(const std::string &path, std::string &out)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    out = buffer.str();
    return true;
}

// Accepts "0x8919b59", "143760217" and plain decimals.
inline std::optional<std::uint64_t> parse_u64(const std::string &text)
{
    const auto value = trim(text);
    if (value.empty()) {
        return std::nullopt;
    }
    try {
        std::size_t consumed = 0;
        const int base = (value.size() > 2 && value[0] == '0' &&
                          (value[1] == 'x' || value[1] == 'X')) ? 16 : 10;
        const auto result = std::stoull(value, &consumed, base);
        if (consumed != value.size()) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(result);
    }
    catch (...) {
        return std::nullopt;
    }
}

inline bool parse_bool(const std::string &text, bool fallback)
{
    const auto value = trim(text);
    if (value == "true" || value == "1") {
        return true;
    }
    if (value == "false" || value == "0") {
        return false;
    }
    return fallback;
}

// "E8 52 07 00 00 80 BC 24" -> raw bytes. False on malformed input.
inline bool parse_hex_bytes(const std::string &text, std::string &out)
{
    std::string bytes;
    int nibble = -1;
    for (const char c : text) {
        int value;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        }
        else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        }
        else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        }
        else {
            continue;  // spaces, dashes, commas
        }
        if (nibble < 0) {
            nibble = value;
        }
        else {
            bytes.push_back(static_cast<char>((nibble << 4) | value));
            nibble = -1;
        }
    }
    if (nibble >= 0 || bytes.empty()) {
        return false;
    }
    out = bytes;
    return true;
}

}  // namespace xuidforward
