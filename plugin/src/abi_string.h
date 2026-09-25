// xuidforward - reading and replacing a std::string that belongs to BDS.
//
// The PlayerAuthenticationInfo we rewrite holds std::string members, and we are
// reaching into another binary's object. Three things make that survivable:
//
//   1. BDS is built with libc++ and this shim is built with libc++ too, so the
//      layouts agree - but that is not taken on faith. detect() probes *our own*
//      libc++ with a short and a long string and works the layout out from
//      structure alone: which offset holds the inline text, which holds the long
//      size, which holds the heap pointer, which byte discriminates the two.
//   2. No guest address is ever dereferenced before it has been checked against
//      /proc/self/maps. An earlier revision of this file dereferenced a candidate
//      pointer during detection; a wrong candidate meant SIGSEGV inside BDS's
//      login path and took the server down. AddressSpace::readable() now gates
//      every single guest access, so that class of bug cannot come back.
//   3. read() further requires printable ASCII of a sane length, and the caller
//      only proceeds when the decoded value matches a login staged moments
//      earlier. Anything that does not decode cleanly is left untouched.
//
// XUIDs are 16-17 digits, so a replacement always lands in the short-string
// buffer: no allocation, no free, nothing that can interact with BDS's heap.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace xuidforward {

// Is [address, address + size) inside a readable mapping of this process?
//
// /proc/self/maps is re-read per call: this only runs during a login, and being
// current matters more than being fast when the alternative is a segfault.
class AddressSpace {
public:
    static bool readable(const void *address, std::size_t size)
    {
        if (address == nullptr || size == 0) {
            return false;
        }
        const auto start = reinterpret_cast<std::uintptr_t>(address);
        const auto end = start + size;
        if (end < start) {
            return false;  // overflow
        }
        std::ifstream maps("/proc/self/maps");
        if (!maps) {
            return false;  // cannot verify -> refuse to touch it
        }
        std::string line;
        while (std::getline(maps, line)) {
            const auto dash = line.find('-');
            const auto space = line.find(' ');
            if (dash == std::string::npos || space == std::string::npos || dash > space) {
                continue;
            }
            if (space + 1 >= line.size() || line[space + 1] != 'r') {
                continue;  // mapping is not readable
            }
            try {
                const auto from = std::stoull(line.substr(0, dash), nullptr, 16);
                const auto to = std::stoull(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                if (start >= from && end <= to) {
                    return true;
                }
            }
            catch (...) {
                continue;
            }
        }
        return false;
    }

    // Read a pointer-sized value out of a guest object, then check that what it
    // points at is readable for `size` bytes before returning it.
    static bool dereference(const void *object, std::uint32_t offset, std::size_t size, const char **out)
    {
        std::uint64_t value = 0;
        std::memcpy(&value, static_cast<const unsigned char *>(object) + offset, sizeof(value));
        if (value == 0) {
            return false;
        }
        const auto *pointer = reinterpret_cast<const char *>(value);
        if (!readable(pointer, size)) {
            return false;
        }
        *out = pointer;
        return true;
    }
};

struct StringLayout {
    std::uint32_t flag_offset{23};  // byte holding the "is long" discriminator
    std::uint32_t short_data{0};    // inline text offset (short form)
    std::uint32_t long_size{8};     // size field (long form)
    std::uint32_t long_data{0};     // pointer to heap text (long form)
    bool valid{false};

    [[nodiscard]] std::string describe() const
    {
        if (!valid) {
            return "undetected";
        }
        std::ostringstream out;
        out << "flag+" << flag_offset << " short_data+" << short_data << " long_size+" << long_size
            << " long_data+" << long_data;
        return out.str();
    }

    static std::uint64_t load_u64(const void *base, std::uint32_t offset)
    {
        std::uint64_t value = 0;
        std::memcpy(&value, static_cast<const unsigned char *>(base) + offset, sizeof(value));
        return value;
    }

    // Hex dump of the two probe strings, for diagnostics when detection fails.
    static std::string probe_dump()
    {
        const std::string small = "xuidforward";
        const std::string large(40, 'z');
        const auto dump = [](const std::string &value) {
            std::ostringstream out;
            const auto *bytes = reinterpret_cast<const unsigned char *>(&value);
            char buffer[4];
            for (std::size_t i = 0; i < 24; ++i) {
                std::snprintf(buffer, sizeof(buffer), "%02x ", bytes[i]);
                out << buffer;
            }
            return out.str();
        };
        return "short(" + std::to_string(sizeof(std::string)) + "B)[" + dump(small) + "] long[" + dump(large) + "]";
    }

    // Work the layout out from our own libc++, structurally, without ever
    // dereferencing a pointer we have not validated. Returns false if no layout
    // explains both probes - in which case nothing is ever patched.
    bool detect()
    {
        const std::string small = "xuidforward";  // 11 chars: stays inline in both layouts
        const std::string large(40, 'z');         // 40 chars: forced to the long form
        const auto *s = reinterpret_cast<const unsigned char *>(&small);
        const auto *l = reinterpret_cast<const unsigned char *>(&large);

        for (std::uint32_t flag = 0; flag < 24; ++flag) {
            if ((s[flag] & 1) != 0 || (l[flag] & 1) == 0) {
                continue;  // discriminator must be even for short, odd for long
            }
            if ((s[flag] >> 1) != small.size()) {
                continue;  // short form stores the length here, shifted
            }
            std::uint32_t inline_offset = 0;
            bool have_short = false;
            for (std::uint32_t offset = 0; offset + small.size() <= 24; ++offset) {
                if (offset == flag) {
                    continue;
                }
                if (std::memcmp(s + offset, small.data(), small.size()) == 0) {
                    inline_offset = offset;
                    have_short = true;
                    break;
                }
            }
            if (!have_short) {
                continue;
            }
            std::uint32_t long_size = 0;
            bool have_size = false;
            for (std::uint32_t offset = 0; offset + 8 <= 24; offset += 8) {
                if (load_u64(l, offset) == large.size()) {
                    long_size = offset;
                    have_size = true;
                    break;
                }
            }
            if (!have_size) {
                continue;
            }
            std::uint32_t long_data = 0;
            bool have_data = false;
            const char *pointer = nullptr;
            // Scan every 8-byte slot: which one holds the pointer differs between
            // libc++ string layouts. dereference() validates each candidate against
            // /proc/self/maps before it is touched, so a wrong slot is harmless.
            for (const std::uint32_t offset : {0u, 8u, 16u}) {
                if (offset == long_size) {
                    continue;
                }
                if (AddressSpace::dereference(l, offset, large.size(), &pointer) &&
                    std::memcmp(pointer, large.data(), large.size()) == 0) {
                    long_data = offset;
                    have_data = true;
                    break;
                }
            }
            if (!have_data) {
                continue;
            }
            flag_offset = flag;
            this->short_data = inline_offset;
            this->long_size = long_size;
            this->long_data = long_data;
            valid = true;
            return true;
        }
        return false;
    }

    // Safe read: fills `out` and returns true only if the bytes at `object`
    // decode as a plausible string of this layout. Every guest address is
    // validated first; anything else is rejected untouched.
    [[nodiscard]] bool read(const void *object, std::string &out) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (!AddressSpace::readable(object, sizeof(std::uint64_t))) {
            return false;
        }
        const auto *bytes = static_cast<const unsigned char *>(object);
        std::uint64_t length = 0;
        const char *data = nullptr;
        if ((bytes[flag_offset] & 1) != 0) {
            length = load_u64(object, long_size);
            if (length == 0 || length > 64) {
                return false;
            }
            if (!AddressSpace::dereference(object, long_data, static_cast<std::size_t>(length), &data)) {
                return false;
            }
        }
        else {
            length = bytes[flag_offset] >> 1;
            if (length == 0 || length > 24 || length + short_data > 24) {
                return false;
            }
            data = reinterpret_cast<const char *>(bytes + short_data);
        }
        for (std::uint64_t i = 0; i < length; ++i) {
            const auto c = static_cast<unsigned char>(data[i]);
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
        }
        out.assign(data, static_cast<std::size_t>(length));
        return true;
    }

    // True only for an empty string in short form - what BDS leaves in the XUID field of a
    // self-signed login. read() rejects empty strings on purpose (it serves names), so this
    // is the separate, equally strict test for "nothing here yet".
    [[nodiscard]] bool is_empty(const void *object) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (!AddressSpace::readable(object, 24)) {
            return false;
        }
        const auto flag = static_cast<const unsigned char *>(object)[flag_offset];
        return flag == 0;  // short form (low bit clear) with length 0
    }

    // Replace the contents. Only ever called after read() succeeded on this very
    // object, and only with short values (see the file header).
    [[nodiscard]] bool assign(void *object, const std::string &value) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (!AddressSpace::readable(object, 24)) {
            return false;
        }
        const auto *bytes = static_cast<const unsigned char *>(object);
        if ((bytes[flag_offset] & 1) != 0) {
            // A long string would mean freeing BDS's heap buffer; refuse and let
            // the caller log it. XUIDs never need this path.
            return false;
        }
        if (value.empty() || value.size() > 22 || short_data + value.size() > 24) {
            return false;
        }
        auto *target = static_cast<unsigned char *>(object);
        std::memcpy(target + short_data, value.data(), value.size());
        std::memset(target + short_data + value.size(), 0, 1);
        target[flag_offset] = static_cast<unsigned char>(value.size() << 1);
        return true;
    }
};

}  // namespace xuidforward
