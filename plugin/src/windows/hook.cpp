// xuidforward (Windows) - the code patch itself.
//
// Same idea as the Linux build: replace the 5-byte `call` at the profile's site with a
// 5-byte `call` to a relay we write within rel32 range. The relay saves all state,
// re-issues the original call (so BDS builds the login result exactly as before), hands the
// result object to the plugin, then restores and returns. Two things differ from Linux:
//   - memory ops use VirtualAlloc/VirtualProtect instead of mmap/mprotect;
//   - the relay follows the Win64 ABI: 32 bytes of shadow space around each call, and the
//     plugin is called with rcx/rdx/r8/r9 (not rdi/rsi/rdx/rcx). The result object the hooked
//     copy constructor built is at the caller's destination, held in r14 across the call.
#include "hook.h"

#include <cstring>

#include <windows.h>

namespace xuidforward {
namespace {

constexpr std::uint32_t kFrame = 0x220;
constexpr std::uint32_t kXmmBase = 0x000;
constexpr std::uint32_t kSavedBase = kFrame;
constexpr std::uint32_t kSavedR14 = kSavedBase + 0x08;
constexpr std::uint32_t kSavedRdi = kSavedBase + 0x40;
constexpr std::uint32_t kSavedRbx = kSavedBase + 0x58;
constexpr std::uint32_t kSavedRax = kSavedBase + 0x70;

constexpr std::uint8_t kRax = 0;
constexpr std::uint8_t kRcx = 1;

class Emitter {
public:
    void byte(std::uint8_t v) { code_.push_back(v); }
    void imm32(std::uint32_t v) { for (int i = 0; i < 4; ++i) byte((v >> (8 * i)) & 0xFF); }
    void imm64(std::uint64_t v) { for (int i = 0; i < 8; ++i) byte((v >> (8 * i)) & 0xFF); }
    void pushfq() { byte(0x9C); }
    void popfq() { byte(0x9D); }
    void ret() { byte(0xC3); }
    void call_rax() { byte(0xFF); byte(0xD0); }

    void push_reg(std::uint8_t r) { if (r >= 8) byte(0x41); byte(0x50 + (r & 7)); }
    void pop_reg(std::uint8_t r) { if (r >= 8) byte(0x41); byte(0x58 + (r & 7)); }

    void sub_rsp(std::uint32_t n) { byte(0x48); byte(0x81); byte(0xEC); imm32(n); }
    void add_rsp(std::uint32_t n) { byte(0x48); byte(0x81); byte(0xC4); imm32(n); }

    void mov_reg_imm64(std::uint8_t r, std::uint64_t v)
    {
        byte(0x48 | (r >= 8 ? 0x01 : 0x00));
        byte(0xB8 + (r & 7));
        imm64(v);
    }

    void raw(std::initializer_list<std::uint8_t> bs) { for (auto b : bs) byte(b); }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(code_); }

private:
    std::vector<std::uint8_t> code_;
};

// mov reg, [rsp + disp32]
void load_reg_rsp(Emitter &e, std::uint8_t reg, std::uint32_t disp)
{
    e.byte(0x48 | (reg >= 8 ? 0x04 : 0x00));
    e.byte(0x8B);
    e.byte(0x84 | ((reg & 7) << 3));
    e.byte(0x24);
    e.imm32(disp);
}

// mov [rsp + disp32], reg
void store_rsp_reg(Emitter &e, std::uint8_t reg, std::uint32_t disp)
{
    e.byte(0x48 | (reg >= 8 ? 0x04 : 0x00));
    e.byte(0x89);
    e.byte(0x84 | ((reg & 7) << 3));
    e.byte(0x24);
    e.imm32(disp);
}

void store_rsp_xmm(Emitter &e, std::uint8_t xmm, std::uint32_t disp)
{
    if (xmm >= 8) e.byte(0x44);
    e.byte(0x0F); e.byte(0x11);
    e.byte(0x84 | ((xmm & 7) << 3));
    e.byte(0x24); e.imm32(disp);
}

void load_rsp_xmm(Emitter &e, std::uint8_t xmm, std::uint32_t disp)
{
    if (xmm >= 8) e.byte(0x44);
    e.byte(0x0F); e.byte(0x10);
    e.byte(0x84 | ((xmm & 7) << 3));
    e.byte(0x24); e.imm32(disp);
}

std::uintptr_t page_start(std::uintptr_t a) { return a & ~static_cast<std::uintptr_t>(4095); }

struct InstalledPatch {
    std::uintptr_t site{0};
    std::uintptr_t relay{0};
    std::size_t size{0};
};
InstalledPatch g_installed;

// The result register the current build_relay() should read. Set by install() from the
// profile; Windows profiles use "r14" (the copy constructor's destination). "rdi"/"rbx" are
// accepted too, for symmetry with the Linux contract.
std::string g_result_reg = "r14";

std::uint32_t saved_result_offset()
{
    if (g_result_reg == "rbx") return kSavedRbx;
    if (g_result_reg == "rdi") return kSavedRdi;
    return kSavedR14;
}

void *alloc_near(std::uintptr_t near_addr, std::size_t size)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    constexpr std::uintptr_t kLimit = 0x60000000;  // stay well inside rel32 range
    for (std::uintptr_t delta = gran; delta < kLimit; delta += gran) {
        for (const int dir : {-1, 1}) {
            const auto cand = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(near_addr) + static_cast<std::intptr_t>(delta) * dir);
            if (cand < 0x10000) {
                continue;
            }
            void *mapped = VirtualAlloc(reinterpret_cast<LPVOID>(page_start(cand)), size,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (mapped == nullptr) {
                continue;
            }
            const auto distance = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(mapped)) -
                                  static_cast<std::int64_t>(near_addr);
            if (distance > INT32_MIN && distance < INT32_MAX) {
                return mapped;
            }
            VirtualFree(mapped, 0, MEM_RELEASE);
        }
    }
    return nullptr;
}

bool protect(void *address, std::size_t length, DWORD flags)
{
    DWORD old = 0;
    return VirtualProtect(address, length, flags, &old) != 0;
}

}  // namespace

const char *relay_register_contract()
{
    return "the PlayerAuthenticationInfo the hooked copy constructor built is handed to the plugin "
           "(profile result_register: r14 = the copy's destination on Windows BDS)";
}

std::vector<std::uint8_t> build_relay(std::uintptr_t helper_address, std::uintptr_t inject_address,
                                      bool /*result_in_rdi, unused on Windows*/)
{
    Emitter e;

    // 1. Save flags, every GPR, and xmm0-15 (BDS may hold live values in xmm here).
    e.pushfq();
    static constexpr std::uint8_t kSave[] = {kRax, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    for (const auto r : kSave) {
        e.push_reg(r);
    }
    e.sub_rsp(kFrame);
    for (int x = 0; x < 16; ++x) {
        store_rsp_xmm(e, static_cast<std::uint8_t>(x), kXmmBase + static_cast<std::uint32_t>(x) * 16);
    }

    // 2. Re-issue the original call. Guest rcx/rdx/r8/r9 are untouched by the saves above, so the
    //    copy constructor runs exactly as BDS called it. Win64 needs 32 bytes of shadow space and
    //    a 16-aligned rsp at the call.
    e.mov_reg_imm64(kRax, helper_address);
    e.sub_rsp(0x28);
    e.call_rax();
    e.add_rsp(0x28);

    // 3. Preserve the call's return value where `pop rax` will restore it.
    store_rsp_reg(e, kRax, kSavedRax);

    // 4. inject(result, 0, 0, 0) - Win64: rcx = result object, the rest unused.
    load_reg_rsp(e, kRcx, saved_result_offset());
    e.raw({0x31, 0xD2});              // xor edx, edx
    e.raw({0x45, 0x31, 0xC0});        // xor r8d, r8d
    e.raw({0x45, 0x31, 0xC9});        // xor r9d, r9d
    e.mov_reg_imm64(kRax, inject_address);
    e.sub_rsp(0x28);
    e.call_rax();
    e.add_rsp(0x28);

    // 5. Restore and return to the instruction after the patched call.
    for (int x = 0; x < 16; ++x) {
        load_rsp_xmm(e, static_cast<std::uint8_t>(x), kXmmBase + static_cast<std::uint32_t>(x) * 16);
    }
    e.add_rsp(kFrame);
    static constexpr std::uint8_t kRestore[] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 3, 2, 1, kRax};
    for (const auto r : kRestore) {
        e.pop_reg(r);
    }
    e.popfq();
    e.ret();

    return e.take();
}

SiteHook::~SiteHook() { remove(); }

bool SiteHook::install(std::uintptr_t base, const Profile &profile, InjectFn inject, std::string &error)
{
    if (installed_) {
        error = "hook is already installed";
        return false;
    }

    Profile resolved = profile;
    if (!resolve_site(resolved, base, error)) {
        return false;
    }
    g_result_reg = resolved.result_register.empty() ? "r14" : resolved.result_register;

    const auto site = base + resolved.site_rva;
    const auto helper = base + resolved.helper_rva;

    if (g_installed.site == site && g_installed.relay != 0) {
        relay_code_ = build_relay(helper, reinterpret_cast<std::uintptr_t>(inject), false);
        relay_ = g_installed.relay;
        relay_size_ = g_installed.size;
        site_ = site;
        installed_ = true;
        return true;
    }

    relay_code_ = build_relay(helper, reinterpret_cast<std::uintptr_t>(inject), false);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const std::size_t page = si.dwPageSize ? si.dwPageSize : 4096;
    relay_size_ = (relay_code_.size() + page - 1) & ~(page - 1);
    relay_ = reinterpret_cast<std::uintptr_t>(alloc_near(site, relay_size_ == 0 ? page : relay_size_));
    if (relay_ == 0) {
        error = "could not allocate executable memory within rel32 range of the hook site";
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(relay_), relay_code_.data(), relay_code_.size());
    if (!protect(reinterpret_cast<void *>(relay_), relay_code_.size(), PAGE_EXECUTE_READ)) {
        error = "VirtualProtect on the relay failed";
        VirtualFree(reinterpret_cast<void *>(relay_), 0, MEM_RELEASE);
        relay_ = 0;
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(relay_), relay_code_.size());

    const auto distance = static_cast<std::int64_t>(relay_) - static_cast<std::int64_t>(site + 5);
    if (distance <= INT32_MIN || distance >= INT32_MAX) {
        error = "relay is out of rel32 range";
        return false;
    }
    const auto *original = reinterpret_cast<const char *>(site);
    original_bytes_.assign(original, 5);

    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void *>(site), 5, PAGE_EXECUTE_READWRITE, &old)) {
        error = "VirtualProtect on the hook site failed";
        return false;
    }
    auto *patch = reinterpret_cast<std::uint8_t *>(site);
    patch[0] = 0xE8;
    const auto rel = static_cast<std::int32_t>(distance);
    std::memcpy(patch + 1, &rel, 4);
    DWORD discard = 0;
    VirtualProtect(reinterpret_cast<void *>(site), 5, old, &discard);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void *>(site), 5);

    site_ = site;
    installed_ = true;
    g_installed = InstalledPatch{site_, relay_, relay_size_};
    return true;
}

void SiteHook::remove()
{
    // As on Linux: leave the patch in place and the relay page mapped. A login thread may be
    // inside the relay right now; unmapping it would crash BDS. Disabling writes is the caller's
    // job (inject_enable(false)) - the relay then just re-issues the original call.
    installed_ = false;
}

}  // namespace xuidforward
