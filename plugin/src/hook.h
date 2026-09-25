// xuidforward - the code patch itself.
//
// The profile points at a single `call` inside BDS's login validation. We
// replace that 5-byte instruction with a 5-byte call to a relay stub we write
// into memory allocated within rel32 range of the site. The stub:
//
//   1. saves the full machine state (flags, all GPRs, xmm0-15 - the surrounding
//      BDS code may hold values in xmm across this call),
//   2. re-issues the original call, so the login result is built exactly as
//      before (we changed nothing about BDS's own logic),
//   3. calls into the plugin with the guest registers the profile documents, to
//      rewrite the XUID in the result,
//   4. restores every register (including the original call's return value in
//      rax) and returns to the instruction after the patched call.
//
// Because the replaced instruction is itself a call, both sides see the same
// return address and stack layout - no instruction relocation, no trampoline
// copying, nothing that can drift with a compiler change.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "profile.h"

namespace xuidforward {

// Invoked from the relay with the registers captured at the hook site.
using InjectFn = void (*)(void *rbx, void *r12, void *r14, void *r15);

class SiteHook {
public:
    SiteHook() = default;
    ~SiteHook();
    SiteHook(const SiteHook &) = delete;
    SiteHook &operator=(const SiteHook &) = delete;

    // Verifies the image against the profile, builds the relay and patches the
    // call site. Fills `error` and returns false without patching anything if
    // any check fails.
    bool install(std::uintptr_t base, const Profile &profile, InjectFn inject, std::string &error);

    // Puts the original instruction back and releases the relay page.
    void remove();

    [[nodiscard]] bool installed() const { return installed_; }
    [[nodiscard]] std::uintptr_t site_address() const { return site_; }
    [[nodiscard]] std::uintptr_t relay_address() const { return relay_; }
    [[nodiscard]] const std::vector<std::uint8_t> &relay_bytes() const { return relay_code_; }

private:
    std::uintptr_t site_{0};
    std::uintptr_t relay_{0};
    std::size_t relay_size_{0};
    std::string original_bytes_;
    std::vector<std::uint8_t> relay_code_;
    bool installed_{false};
};

// Builds the relay machine code (exposed for the self-test command).
std::vector<std::uint8_t> build_relay(std::uintptr_t helper_address, std::uintptr_t inject_address);

// Human-readable register contract read at the hook site (documentation/logs).
const char *relay_register_contract();

}  // namespace xuidforward
