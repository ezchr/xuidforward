#include "hook.h"

#include <cerrno>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace xuidforward {
namespace {

// Frame layout inside the relay (relative to rsp after `sub rsp, kFrame`).
constexpr std::uint32_t kFrame = 0x220;      // keeps the saved block reachable
constexpr std::uint32_t kXmmBase = 0x000;    // 16 * 16 bytes of xmm0-15
constexpr std::uint32_t kSavedBase = kFrame; // pushed registers, in push order
// kSavedBase + offset, indexed by push order:
//   r15 0x00, r14 0x08, r13 0x10, r12 0x18, r11 0x20, r10 0x28, r9 0x30, r8 0x38,
//   rdi 0x40, rsi 0x48, rbp 0x50, rbx 0x58, rdx 0x60, rcx 0x68, rax 0x70, flags 0x78
constexpr std::uint32_t kSavedR15 = kSavedBase + 0x00;
constexpr std::uint32_t kSavedR14 = kSavedBase + 0x08;
constexpr std::uint32_t kSavedR12 = kSavedBase + 0x18;
constexpr std::uint32_t kSavedRbx = kSavedBase + 0x58;
constexpr std::uint32_t kSavedRax = kSavedBase + 0x70;

constexpr std::uint8_t kRax = 0;
constexpr std::uint8_t kRcx = 1;
constexpr std::uint8_t kRdx = 2;
constexpr std::uint8_t kRbx = 3;
constexpr std::uint8_t kRbp = 5;
constexpr std::uint8_t kRsi = 6;
constexpr std::uint8_t kRdi = 7;

class Emitter {
public:
    void byte(std::uint8_t value) { code_.push_back(value); }

    void imm32(std::uint32_t value)
    {
        for (int i = 0; i < 4; ++i) {
            code_.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
        }
    }

    void imm64(std::uint64_t value)
    {
        for (int i = 0; i < 8; ++i) {
            code_.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
        }
    }

    void pushfq() { byte(0x9C); }
    void popfq() { byte(0x9D); }
    void ret() { byte(0xC3); }
    void call_rax() { byte(0xFF); byte(0xD0); }

    void push_reg(std::uint8_t reg)
    {
        if (reg >= 8) {
            byte(0x41);
        }
        byte(static_cast<std::uint8_t>(0x50 + (reg & 7)));
    }

    void pop_reg(std::uint8_t reg)
    {
        if (reg >= 8) {
            byte(0x41);
        }
        byte(static_cast<std::uint8_t>(0x58 + (reg & 7)));
    }

    void sub_rsp(std::uint32_t amount)
    {
        byte(0x48); byte(0x81); byte(0xEC);
        imm32(amount);
    }

    void add_rsp(std::uint32_t amount)
    {
        byte(0x48); byte(0x81); byte(0xC4);
        imm32(amount);
    }

    void mov_reg_imm64(std::uint8_t reg, std::uint64_t value)
    {
        byte(static_cast<std::uint8_t>(0x48 | (reg >= 8 ? 0x01 : 0x00)));
        byte(static_cast<std::uint8_t>(0xB8 + (reg & 7)));
        imm64(value);
    }

    [[nodiscard]] std::vector<std::uint8_t> take() { return std::move(code_); }

private:
    std::vector<std::uint8_t> code_;
};

// mov reg, [rsp + disp32]
void emit_load_reg_rsp(Emitter &e, std::uint8_t reg, std::uint32_t disp)
{
    e.byte(static_cast<std::uint8_t>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
    e.byte(0x8B);
    e.byte(static_cast<std::uint8_t>(0x84 | ((reg & 7) << 3)));
    e.byte(0x24);
    e.imm32(disp);
}

// mov [rsp + disp32], reg
void emit_store_rsp_reg(Emitter &e, std::uint8_t reg, std::uint32_t disp)
{
    e.byte(static_cast<std::uint8_t>(0x48 | (reg >= 8 ? 0x04 : 0x00)));
    e.byte(0x89);
    e.byte(static_cast<std::uint8_t>(0x84 | ((reg & 7) << 3)));
    e.byte(0x24);
    e.imm32(disp);
}

// movups [rsp + disp32], xmm  (unaligned on purpose: the frame is 8 mod 16)
void emit_store_rsp_xmm(Emitter &e, std::uint8_t xmm, std::uint32_t disp)
{
    if (xmm >= 8) {
        e.byte(0x44);
    }
    e.byte(0x0F);
    e.byte(0x11);
    e.byte(static_cast<std::uint8_t>(0x84 | ((xmm & 7) << 3)));
    e.byte(0x24);
    e.imm32(disp);
}

// movups xmm, [rsp + disp32]
void emit_load_rsp_xmm(Emitter &e, std::uint8_t xmm, std::uint32_t disp)
{
    if (xmm >= 8) {
        e.byte(0x44);
    }
    e.byte(0x0F);
    e.byte(0x10);
    e.byte(static_cast<std::uint8_t>(0x84 | ((xmm & 7) << 3)));
    e.byte(0x24);
    e.imm32(disp);
}

std::uintptr_t page_start(std::uintptr_t address)
{
    return address & ~static_cast<std::uintptr_t>(4095);
}

// A patch this process installed, remembered so a re-install can recognise its own
// work: remove() leaves the call patched and the relay page mapped on purpose.
struct InstalledPatch {
    std::uintptr_t site{0};
    std::uintptr_t relay{0};
    std::size_t size{0};
};

InstalledPatch g_installed;

// Allocates executable memory as close as possible to `near`, so that a rel32
// call from the hook site can reach it.
void *alloc_near(std::uintptr_t near, std::size_t size)
{
    constexpr std::uintptr_t kStep = 0x10000;
    constexpr std::uintptr_t kLimit = 0x60000000;  // stay well inside rel32 range
    for (std::uintptr_t delta = kStep; delta < kLimit; delta += kStep) {
        for (const int direction : {-1, 1}) {
            const auto candidate = static_cast<std::uintptr_t>(
                static_cast<std::intptr_t>(near) + static_cast<std::intptr_t>(delta) * direction);
            if (candidate < 0x10000) {
                continue;
            }
            void *mapped = mmap(reinterpret_cast<void *>(page_start(candidate)), size,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (mapped == MAP_FAILED) {
                continue;
            }
            const auto distance = static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(mapped)) -
                                  static_cast<std::int64_t>(near);
            if (distance > INT32_MIN && distance < INT32_MAX) {
                return mapped;
            }
            munmap(mapped, size);
        }
    }
    return nullptr;
}

bool make_writable(void *address, std::size_t length)
{
    const auto start = page_start(reinterpret_cast<std::uintptr_t>(address));
    const auto end = page_start(reinterpret_cast<std::uintptr_t>(address) + length - 1);
    const auto span = end - start + 4096;
    return mprotect(reinterpret_cast<void *>(start), span, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

bool make_executable(void *address, std::size_t length)
{
    const auto start = page_start(reinterpret_cast<std::uintptr_t>(address));
    const auto end = page_start(reinterpret_cast<std::uintptr_t>(address) + length - 1);
    const auto span = end - start + 4096;
    return mprotect(reinterpret_cast<void *>(start), span, PROT_READ | PROT_EXEC) == 0;
}

}  // namespace

const char *relay_register_contract()
{
    return "rbx = pointer to the optional<PlayerAuthenticationInfo> result, "
           "r12 = LoginPacket, r14 = this (ServerNetworkHandler), r15 = NetworkIdentifier";
}

std::vector<std::uint8_t> build_relay(std::uintptr_t helper_address, std::uintptr_t inject_address)
{
    Emitter e;

    // 1. Save everything we are about to touch. The BDS code around this call
    //    may be holding live values in xmm registers, so those are saved too.
    e.pushfq();
    static constexpr std::uint8_t kSaveOrder[] = {kRax, kRcx, kRdx, kRbx, kRbp, kRsi, kRdi,
                                                  8, 9, 10, 11, 12, 13, 14, 15};
    for (const auto reg : kSaveOrder) {
        e.push_reg(reg);
    }
    e.sub_rsp(kFrame);
    for (int xmm = 0; xmm < 16; ++xmm) {
        emit_store_rsp_xmm(e, static_cast<std::uint8_t>(xmm),
                           kXmmBase + static_cast<std::uint32_t>(xmm) * 16);
    }

    // 2. Re-issue the original call, so the login result is built exactly as
    //    BDS would have built it. Align the stack for the call: after the
    //    prologue rsp is 8 (mod 16), and a call needs 0 (mod 16).
    e.mov_reg_imm64(kRax, helper_address);
    e.sub_rsp(8);
    e.call_rax();
    e.add_rsp(8);

    // 3. Keep the call's return value where `pop rax` will pick it up. The
    //    caller may rely on it (the register contract says the result pointer
    //    arrives in rbx, but preserving rax costs nothing and removes doubt).
    emit_store_rsp_reg(e, kRax, kSavedRax);

    // 4. Hand the guest registers to the plugin:
    //    inject(rbx, r12, r14, r15)
    emit_load_reg_rsp(e, kRdi, kSavedRbx);
    emit_load_reg_rsp(e, kRsi, kSavedR12);
    emit_load_reg_rsp(e, kRdx, kSavedR14);
    emit_load_reg_rsp(e, kRcx, kSavedR15);
    e.mov_reg_imm64(kRax, inject_address);
    e.sub_rsp(8);
    e.call_rax();
    e.add_rsp(8);

    // 5. Restore and return to the instruction after the patched call.
    for (int xmm = 0; xmm < 16; ++xmm) {
        emit_load_rsp_xmm(e, static_cast<std::uint8_t>(xmm),
                          kXmmBase + static_cast<std::uint32_t>(xmm) * 16);
    }
    e.add_rsp(kFrame);
    static constexpr std::uint8_t kRestoreOrder[] = {15, 14, 13, 12, 11, 10, 9, 8, kRdi, kRsi,
                                                     kRbp, kRbx, kRdx, kRcx, kRax};
    for (const auto reg : kRestoreOrder) {
        e.pop_reg(reg);
    }
    e.popfq();
    e.ret();

    return e.take();
}

SiteHook::~SiteHook()
{
    remove();
}

bool SiteHook::install(std::uintptr_t base, const Profile &profile, InjectFn inject, std::string &error)
{
    if (installed_) {
        error = "hook is already installed";
        return false;
    }

    // Locate (and verify) the site first: a signature profile has no site_rva until this runs, so
    // everything below - including the re-install shortcut - must use the resolved copy.
    Profile resolved = profile;
    if (!resolve_site(resolved, base, error)) {
        return false;
    }

    const auto site = base + resolved.site_rva;
    const auto helper = base + resolved.helper_rva;

    // remove() intentionally leaves the patch in place and the relay page mapped, so a
    // later install in the same process is looking at bytes it wrote itself. Recognise
    // that case and just re-point at the existing relay instead of patching twice.
    if (g_installed.site == site && g_installed.relay != 0) {
        relay_code_ = build_relay(helper, reinterpret_cast<std::uintptr_t>(inject));
        relay_ = g_installed.relay;
        relay_size_ = g_installed.size;
        site_ = site;
        installed_ = true;
        return true;
    }

    relay_code_ = build_relay(helper, reinterpret_cast<std::uintptr_t>(inject));

    const std::size_t page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    relay_size_ = (relay_code_.size() + page - 1) & ~(page - 1);
    relay_ = reinterpret_cast<std::uintptr_t>(
        alloc_near(site, relay_size_ == 0 ? page : relay_size_));
    if (relay_ == 0) {
        error = "could not allocate executable memory within rel32 range of the hook site";
        return false;
    }
    std::memcpy(reinterpret_cast<void *>(relay_), relay_code_.data(), relay_code_.size());
    if (!make_executable(reinterpret_cast<void *>(relay_), relay_code_.size())) {
        error = std::string("mprotect on the relay failed: ") + std::strerror(errno);
        munmap(reinterpret_cast<void *>(relay_), relay_size_);
        relay_ = 0;
        return false;
    }

    // Patch the site: E8 rel32 -> call relay.
    const auto distance = static_cast<std::int64_t>(relay_) - static_cast<std::int64_t>(site + 5);
    if (distance <= INT32_MIN || distance >= INT32_MAX) {
        error = "relay is out of rel32 range";
        return false;
    }
    const auto *original = reinterpret_cast<const char *>(site);
    original_bytes_.assign(original, 5);
    if (!make_writable(reinterpret_cast<void *>(site), 5)) {
        error = std::string("mprotect on the hook site failed: ") + std::strerror(errno);
        return false;
    }
    auto *patch = reinterpret_cast<std::uint8_t *>(site);
    patch[0] = 0xE8;
    const auto rel = static_cast<std::int32_t>(distance);
    std::memcpy(patch + 1, &rel, 4);
    __builtin___clear_cache(reinterpret_cast<char *>(site), reinterpret_cast<char *>(site) + 5);
    make_executable(reinterpret_cast<void *>(site), 5);

    site_ = site;
    installed_ = true;
    g_installed = InstalledPatch{site_, relay_, relay_size_};
    return true;
}

void SiteHook::remove()
{
    // Deliberately does NOT unmap the relay page and does NOT put the original bytes
    // back. A login thread can be inside the relay (or inside the call it re-issued)
    // at this moment; unmapping the page it must return through would crash BDS, and
    // rewriting the 4-byte displacement is not atomic for a thread already executing
    // it. Disabling injection is done by the caller (inject_enable(false)) - the relay
    // then re-issues the original call and rewrites nothing, which is transparent.
    //
    // The cost is one leaked page per install in a process lifetime, and an unpatched
    // binary the next time the server starts.
    installed_ = false;
}

}  // namespace xuidforward
