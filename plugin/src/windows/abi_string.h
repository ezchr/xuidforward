// xuidforward (Windows) - reading and replacing a std::string that belongs to BDS.
//
// Windows BDS is built with MSVC and dynamically links msvcp140.dll / vcruntime140.dll
// / the UCRT (confirmed from the import table - no CRT ships in the zip). This shim is
// built with the same dynamic CRT (/MD), so its std::string is binary-identical to BDS's
// and shares the same heap. That lets the XUID write go through the *real*
// std::string::assign: allocation and the eventual free both run in msvcp140, so there is
// no SSO-size limit and no heap mismatch (the libc++/Linux build can keep its field in the
// small-string buffer because its SSO holds 22 chars; MSVC's holds only 15, so a 16-17
// digit XUID must allocate - assign does that correctly).
//
// Safety is unchanged from the Linux build: every guest address is validated with
// VirtualQuery before it is touched, reads require printable ASCII of sane length, and the
// write is only ever done to a field that just read back as empty, with a post-write
// read-back tripwire.
#pragma once
// Same guard macro as the libc++ plugin/src/abi_string.h. This file is force-included (/FI) first
// in the Windows build, so when inject.h later does #include "abi_string.h" and MSVC resolves it to
// the sibling libc++ header, that header's body is skipped and this MSVC one is the only layout.
#ifndef XUIDFORWARD_ABI_STRING_H
#define XUIDFORWARD_ABI_STRING_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

#include <windows.h>

namespace xuidforward {

// MSVC std::basic_string<char> layout (x64):
//   +0  union { char buf[16]; char* ptr; }
//   +16 size_t _Mysize
//   +24 size_t _Myres   (capacity; <=15 means the small-string buffer is in use)
constexpr std::uint32_t kMsvcData = 0;
constexpr std::uint32_t kMsvcSize = 16;
constexpr std::uint32_t kMsvcCap = 24;
constexpr std::uint32_t kMsvcStringSize = 32;
constexpr std::uint64_t kMsvcSso = 15;

// Is [address, address+size) backed by committed memory with the required access?
class AddressSpace {
    static bool check(const void *address, std::size_t size, bool need_write)
    {
        if (address == nullptr || size == 0) {
            return false;
        }
        auto p = reinterpret_cast<std::uintptr_t>(address);
        const auto end = p + size;
        if (end < p) {
            return false;  // overflow
        }
        while (p < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) == 0) {
                return false;
            }
            if (mbi.State != MEM_COMMIT) {
                return false;
            }
            const DWORD prot = mbi.Protect;
            if ((prot & PAGE_GUARD) || (prot & PAGE_NOACCESS)) {
                return false;
            }
            const bool readable =
                (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (!readable) {
                return false;
            }
            if (need_write) {
                const bool writable =
                    (prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                             PAGE_EXECUTE_WRITECOPY)) != 0;
                if (!writable) {
                    return false;
                }
            }
            const auto region_end =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (region_end <= p) {
                return false;  // no progress
            }
            p = region_end;
        }
        return true;
    }

public:
    static bool readable(const void *address, std::size_t size) { return check(address, size, false); }
    static bool writable(const void *address, std::size_t size) { return check(address, size, true); }
};

// Keeps the Linux StringLayout interface so inject.cpp and xf_api.cpp are unchanged.
struct StringLayout {
    bool valid{false};

    [[nodiscard]] std::string describe() const
    {
        if (!valid) {
            return "undetected";
        }
        return "MSVC std::string: data+0 size+16 cap+24 (SSO 15)";
    }

    static std::uint64_t load_u64(const void *base, std::uint32_t offset)
    {
        std::uint64_t value = 0;
        std::memcpy(&value, static_cast<const unsigned char *>(base) + offset, sizeof(value));
        return value;
    }

    static std::string probe_dump()
    {
        const std::string small = "xuidforward";
        const std::string large(40, 'z');
        const auto dump = [](const std::string &value) {
            std::ostringstream out;
            const auto *bytes = reinterpret_cast<const unsigned char *>(&value);
            char buffer[4];
            for (std::size_t i = 0; i < kMsvcStringSize; ++i) {
                std::snprintf(buffer, sizeof(buffer), "%02x ", bytes[i]);
                out << buffer;
            }
            return out.str();
        };
        return "short(" + std::to_string(sizeof(std::string)) + "B)[" + dump(small) + "] long[" +
               dump(large) + "]";
    }

    // Confirm, structurally and against our own CRT, that std::string is the layout above.
    // Built with the same msvcp140 as BDS, so this is a check, not an assumption.
    bool detect()
    {
        valid = false;
        if (sizeof(std::string) != kMsvcStringSize) {
            return false;
        }
        const std::string small = "x";        // size 1, inline
        const std::string large(40, 'z');     // size 40, heap
        if (load_u64(&small, kMsvcSize) != 1 || load_u64(&large, kMsvcSize) != 40) {
            return false;
        }
        if (load_u64(&small, kMsvcCap) != kMsvcSso) {
            return false;  // empty/short capacity is exactly the SSO bound
        }
        if (load_u64(&large, kMsvcCap) < 40) {
            return false;
        }
        if (std::memcmp(&small, "x", 1) != 0) {
            return false;  // inline data at +0
        }
        const char *heap = nullptr;
        std::memcpy(&heap, &large, sizeof(heap));  // ptr at +0 for the long form
        if (heap == nullptr || std::memcmp(heap, "zzz", 3) != 0) {
            return false;
        }
        valid = true;
        return true;
    }

    // Read a std::string field into `out`; rejects anything that does not decode as a
    // printable, sanely bounded string. Every guest address is validated first.
    [[nodiscard]] bool read(const void *object, std::string &out) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (!AddressSpace::readable(object, kMsvcStringSize)) {
            return false;
        }
        const std::uint64_t size = load_u64(object, kMsvcSize);
        const std::uint64_t cap = load_u64(object, kMsvcCap);
        if (size == 0 || size > 255 || cap < size) {
            return false;
        }
        const char *data = nullptr;
        if (cap <= kMsvcSso) {
            data = reinterpret_cast<const char *>(object);  // inline buffer
        }
        else {
            std::memcpy(&data, object, sizeof(data));  // heap pointer at +0
            if (!AddressSpace::readable(data, static_cast<std::size_t>(size))) {
                return false;
            }
        }
        for (std::uint64_t i = 0; i < size; ++i) {
            const auto c = static_cast<unsigned char>(data[i]);
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
        }
        out.assign(data, static_cast<std::size_t>(size));
        return true;
    }

    // True only for an empty string - what BDS leaves in the XUID field of a self-signed login.
    [[nodiscard]] bool is_empty(const void *object) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (!AddressSpace::readable(object, kMsvcStringSize)) {
            return false;
        }
        return load_u64(object, kMsvcSize) == 0;
    }

    // Replace the contents. Only ever called after is_empty() held on this object. Uses the real
    // std::string::assign (same msvcp140 as BDS), which allocates when the value does not fit the
    // 15-char small buffer and leaves a string BDS's own destructor can free.
    [[nodiscard]] bool assign(void *object, const std::string &value) const
    {
        if (!valid || object == nullptr || (reinterpret_cast<std::uintptr_t>(object) & 0x7) != 0) {
            return false;
        }
        if (value.empty() || value.size() > 64) {
            return false;
        }
        if (!AddressSpace::writable(object, kMsvcStringSize)) {
            return false;
        }
        try {
            auto *s = reinterpret_cast<std::string *>(object);
            s->assign(value.data(), value.size());
        }
        catch (...) {
            return false;  // bad_alloc or length_error: leave the login untouched
        }
        // Post-write tripwire: read it back and confirm it decodes to exactly what we wrote.
        std::string check;
        if (!read(object, check) || check != value) {
            return false;
        }
        return true;
    }
};

}  // namespace xuidforward

#endif  // XUIDFORWARD_ABI_STRING_H
