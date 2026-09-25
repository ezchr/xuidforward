// xuidforward - rewriting the XUID of a relayed login.
//
// Everything here runs *inside* BDS's login validation, called from the relay
// stub (see hook.h). It is deliberately paranoid: it only ever touches memory it
// has positively identified as the PlayerAuthenticationInfo BDS just built for
// a login it saw milliseconds earlier. Anything unexpected - pointer null or
// misaligned, optional not engaged, name not staged, string does not decode,
// XUID not digits, SelfSignedId not matching the relay's derivation - leaves the
// login untouched and is counted and logged instead.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "abi_string.h"
#include "profile.h"

namespace xuidforward {

struct InjectConfig {
    Profile profile;
    bool enabled{true};
    bool dry_run{true};
    bool require_self_signed_id_match{true};
    bool require_digit_xuid{true};
    int stage_ttl_seconds{30};
    std::array<std::uint8_t, 16> namespace_uuid{};
    std::string namespace_text;
    StringLayout layout;
    std::string plugin_dir;
};

// Configured once, before the hook is installed; read-only afterwards.
void inject_configure(const InjectConfig &config);
const InjectConfig &inject_config();

// Turn injection on/off without touching the code patch. Used by xf_uninstall: the
// patch has to stay in place (unmapping its page while a login thread is inside it
// would crash BDS), so disabling means "the relay stops rewriting anything".
void inject_enable(bool enabled);

struct InjectStats {
    std::uint64_t calls{0};
    std::uint64_t not_engaged{0};
    std::uint64_t name_unreadable{0};
    std::uint64_t name_not_staged{0};
    std::uint64_t injected{0};
    std::uint64_t would_inject{0};  // dry-run
    std::uint64_t write_refused{0};
    std::uint64_t xuid_present{0};  // BDS already had an XUID: never overwritten
};

InjectStats inject_stats_snapshot();

// The relay entry point. Signature is fixed by build_relay(): it receives the
// guest registers captured at the hook site.
void inject_entry(void *optional_result, void *login_packet, void *network_handler, void *network_identifier);

}  // namespace xuidforward
