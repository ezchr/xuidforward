#include "inject.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <unistd.h>

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

// A hook runs in the middle of BDS's login path, so logging must not depend on
// the plugin API (or on anything that can allocate heavily). A plain write() to
// stderr, serialised, keeps this boring and safe.
void hook_log(const char *line)
{
    static std::mutex log_mutex;
    std::lock_guard lock(log_mutex);
    const std::string text = std::string("[xuidforward] ") + line + "\n";
    ssize_t ignored = ::write(STDERR_FILENO, text.data(), text.size());
    (void)ignored;
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

void inject_enable(bool enabled)
{
    g_injection_enabled.store(enabled, std::memory_order_relaxed);
}

const InjectConfig &inject_config()
{
    return g_config;
}

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

    // Nothing staged means no relayed login is in flight - the common case, every
    // native Xbox login. Return before reading /proc/self/maps or any guest memory.
    if (identity_stage().size() == 0) {
        return;
    }

    auto *object = static_cast<unsigned char *>(optional_result);

    // The optional must be engaged: BDS only consumes the result when it is.
    if (object[config.profile.offsets.engaged] == 0) {
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
        // A relayed login *is* staged, yet the name BDS built does not match it. That
        // points straight at the name field (`xname` vs `ThirdPartyName`) and would
        // otherwise be invisible, so say it out loud - rate limited so a flood of
        // unrelated logins cannot fill the console.
        static std::atomic<long long> last_log{0};
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        auto previous = last_log.load(std::memory_order_relaxed);
        if (now - previous > 10'000'000'000LL && last_log.compare_exchange_strong(previous, now)) {
            const std::string line = "a relayed identity is staged [" + identity_stage().staged_names() +
                                     "] but the name in the auth result is '" + name +
                                     "' - name field mismatch?";
            hook_log(line.c_str());
        }
        return;  // a login this plugin did not watch: leave it completely alone
    }

    if (config.require_digit_xuid && !all_digits(staged->xuid)) {
        hook_log("staged xuid is not numeric - refusing");
        g_write_refused.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Only ever fill a blank XUID. A relayed (self-signed) login reaches here with the XUID
    // empty; a genuine Xbox login already carries its own, and that must never be replaced
    // by whatever happens to be staged under the same name.
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
        hook_log("could not write the xuid (string not in short-string form?) - login left untouched");
        g_write_refused.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    g_injected.fetch_add(1, std::memory_order_relaxed);
    const std::string line = "restored xuid=" + staged->xuid + " for relayed player " + name;
    hook_log(line.c_str());
}

}  // namespace xuidforward
