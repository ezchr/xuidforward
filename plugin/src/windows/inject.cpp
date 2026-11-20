// xuidforward (Windows) - rewriting the XUID of a relayed login.
//
// Identical in logic to the Linux inject.cpp; only two things differ: logging goes to
// stderr through the CRT (no unistd ::write), and "plain" (a bare PlayerAuthenticationInfo
// with no engaged flag) is any non-"rbx" result register - on Windows that is "r14", the
// destination the copy constructor wrote.
#include "inject.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>

#include "claims.h"
#include "stage.h"
#include "uuid5.h"

namespace xuidforward {
namespace {

InjectConfig g_config;
std::atomic<bool> g_injection_enabled{false};
std::atomic<std::uint64_t> g_calls{0};
std::atomic<std::uint64_t> g_not_engaged{0};
std::atomic<std::uint64_t> g_name_unreadable{0};
std::atomic<std::uint64_t> g_name_not_staged{0};
std::atomic<std::uint64_t> g_injected{0};
std::atomic<std::uint64_t> g_would_inject{0};
std::atomic<std::uint64_t> g_write_refused{0};
std::atomic<std::uint64_t> g_xuid_present{0};

void hook_log(const char *line)
{
    static std::mutex log_mutex;
    std::lock_guard lock(log_mutex);
    std::fputs("[xuidforward] ", stderr);
    std::fputs(line, stderr);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}

bool all_digits(const std::string &value)
{
    if (value.empty() || value.size() > 32) {
        return false;
    }
    for (const char c : value) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

}  // namespace

void inject_configure(const InjectConfig &config)
{
    g_config = config;
    g_injection_enabled.store(config.enabled, std::memory_order_relaxed);
}

void inject_enable(bool enabled) { g_injection_enabled.store(enabled, std::memory_order_relaxed); }

const InjectConfig &inject_config() { return g_config; }

InjectStats inject_stats_snapshot()
{
    InjectStats stats;
    stats.calls = g_calls.load();
    stats.not_engaged = g_not_engaged.load();
    stats.name_unreadable = g_name_unreadable.load();
    stats.name_not_staged = g_name_not_staged.load();
    stats.injected = g_injected.load();
    stats.would_inject = g_would_inject.load();
    stats.write_refused = g_write_refused.load();
    stats.xuid_present = g_xuid_present.load();
    return stats;
}

void inject_entry(void *optional_result, void *login_packet, void *network_handler, void *network_identifier)
{
    (void)login_packet;
    (void)network_handler;
    (void)network_identifier;

    g_calls.fetch_add(1, std::memory_order_relaxed);
    const InjectConfig &config = g_config;
    if (!g_injection_enabled.load(std::memory_order_relaxed) || optional_result == nullptr) {
        return;
    }

    if (identity_stage().size() == 0) {
        return;
    }

    auto *object = static_cast<unsigned char *>(optional_result);

    const bool plain = config.profile.result_register != "rbx";
    const std::uint64_t span = std::max({plain ? 0 : config.profile.offsets.engaged + 1,
                                         config.profile.offsets.xbox_live_name + config.profile.offsets.string_size,
                                         config.profile.offsets.xuid + config.profile.offsets.string_size});
    if (!AddressSpace::readable(object, static_cast<std::size_t>(span))) {
        g_write_refused.fetch_add(1, std::memory_order_relaxed);
        if (config.dry_run) {
            hook_log("auth-result object is not fully mapped at the profile's offsets - left untouched");
        }
        return;
    }

    if (!plain && object[config.profile.offsets.engaged] == 0) {
        g_not_engaged.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    std::string name;
    if (!config.layout.read(object + config.profile.offsets.xbox_live_name, name)) {
        g_name_unreadable.fetch_add(1, std::memory_order_relaxed);
        if (config.dry_run) {
            hook_log("could not read a player name out of the auth result (layout/offset mismatch?)");
        }
        return;
    }

    auto staged = identity_stage().take(name);
    if (!staged) {
        g_name_not_staged.fetch_add(1, std::memory_order_relaxed);
        static std::atomic<long long> last_log{0};
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto previous = last_log.load(std::memory_order_relaxed);
        if (now - previous > 10'000'000'000LL && last_log.compare_exchange_strong(previous, now)) {
            const std::string line = "a relayed identity is staged [" + identity_stage().staged_names() +
                                     "] but the name in the auth result is '" + name +
                                     "' - name field mismatch?";
            hook_log(line.c_str());
        }
        return;
    }

    if (config.require_digit_xuid && !all_digits(staged->xuid)) {
        hook_log("staged xuid is not numeric - refusing");
        g_write_refused.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    void *xuid_field = object + config.profile.offsets.xuid;
    if (!config.layout.is_empty(xuid_field)) {
        std::string current_xuid;
        if (!config.layout.read(xuid_field, current_xuid)) {
            hook_log("the login's xuid field is neither empty nor readable - login left untouched");
            g_write_refused.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        g_xuid_present.fetch_add(1, std::memory_order_relaxed);
        const std::string line = "login for " + name + " already carries xuid " + current_xuid +
                                 " - staged identity discarded, nothing written";
        hook_log(line.c_str());
        return;
    }

    if (config.dry_run) {
        g_would_inject.fetch_add(1, std::memory_order_relaxed);
        const std::string line = "dry run: would set xuid=" + staged->xuid + " for player " + name +
                                 " (selfSignedId=" + staged->self_signed_id + ")";
        hook_log(line.c_str());
        return;
    }

    if (!config.layout.assign(object + config.profile.offsets.xuid, staged->xuid)) {
        hook_log("could not write the xuid - login left untouched");
        g_write_refused.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    g_injected.fetch_add(1, std::memory_order_relaxed);
    const std::string line = "restored xuid=" + staged->xuid + " for relayed player " + name;
    hook_log(line.c_str());
}

}  // namespace xuidforward
