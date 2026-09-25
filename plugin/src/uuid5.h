// xuidforward - SHA-1 and UUID v5, used to re-derive the SelfSignedId that
// nether2rak puts in the login it forges.
//
// The relay sets `SelfSignedId = uuid5(namespace, realXUID)` (see
// n2rpush/proxy/self_signed_id.go). Being able to recompute that here is what
// makes this plugin fail closed: an injected XUID is only accepted when the
// login's own SelfSignedId matches the XUID it claims, so an arbitrary client
// cannot name someone else's XUID and inherit their player data.
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace xuidforward {

class Sha1 {
public:
    Sha1() { reset(); }

    void reset()
    {
        state_ = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
        length_ = 0;
        buffer_len_ = 0;
    }

    void update(const void *data, std::size_t len)
    {
        const auto *bytes = static_cast<const std::uint8_t *>(data);
        length_ += static_cast<std::uint64_t>(len) * 8;
        while (len > 0) {
            const std::size_t take = std::min(len, 64 - buffer_len_);
            std::memcpy(buffer_ + buffer_len_, bytes, take);
            buffer_len_ += take;
            bytes += take;
            len -= take;
            if (buffer_len_ == 64) {
                process(buffer_);
                buffer_len_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 20> digest()
    {
        const std::uint64_t bit_length = length_;
        const std::uint8_t pad = 0x80;
        update(&pad, 1);
        const std::uint8_t zero = 0;
        while (buffer_len_ != 56) {
            update(&zero, 1);
        }
        std::uint8_t size[8];
        for (int i = 0; i < 8; ++i) {
            size[i] = static_cast<std::uint8_t>((bit_length >> (56 - 8 * i)) & 0xFF);
        }
        update(size, 8);

        std::array<std::uint8_t, 20> out{};
        for (std::size_t i = 0; i < 5; ++i) {
            out[i * 4 + 0] = static_cast<std::uint8_t>(state_[i] >> 24);
            out[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
            out[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
            out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
        }
        return out;
    }

private:
    static std::uint32_t rol(std::uint32_t value, unsigned bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    void process(const std::uint8_t *block)
    {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<std::uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            const std::uint32_t temp = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
    }

    std::array<std::uint32_t, 5> state_{};
    std::uint64_t length_{};
    std::uint8_t buffer_[64]{};
    std::size_t buffer_len_{};
};

// Parses "a3e78ee7-823a-4cb5-9fe0-532b54ccc20d" into 16 bytes.
inline bool parse_uuid(const std::string &text, std::array<std::uint8_t, 16> &out)
{
    std::size_t index = 0;
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
            continue;
        }
        if (nibble < 0) {
            nibble = value;
        }
        else {
            if (index >= 16) {
                return false;
            }
            out[index++] = static_cast<std::uint8_t>((nibble << 4) | value);
            nibble = -1;
        }
    }
    return index == 16 && nibble < 0;
}

inline std::string format_uuid(const std::array<std::uint8_t, 16> &bytes)
{
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out.push_back('-');
        }
        out.push_back(hex[bytes[i] >> 4]);
        out.push_back(hex[bytes[i] & 0x0F]);
    }
    return out;
}

// UUID v5 (SHA-1, RFC 4122) of a name inside a namespace - the same value the
// relay stamps into SelfSignedId for a given XUID.
inline std::string uuid5(const std::array<std::uint8_t, 16> &ns, const std::string &name)
{
    Sha1 sha;
    sha.update(ns.data(), ns.size());
    sha.update(name.data(), name.size());
    auto digest = sha.digest();
    digest[6] = static_cast<std::uint8_t>((digest[6] & 0x0F) | 0x50);  // version 5
    digest[8] = static_cast<std::uint8_t>((digest[8] & 0x3F) | 0x80);  // RFC 4122 variant
    std::array<std::uint8_t, 16> uuid{};
    std::memcpy(uuid.data(), digest.data(), 16);
    return format_uuid(uuid);
}

}  // namespace xuidforward
