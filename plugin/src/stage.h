// xuidforward - pending identities, staged between "a login packet arrived" and
// "BDS built the authentication result for it".
//
// PacketReceiveEvent gives us the login before BDS has finished validating it;
// the hook fires a few hundred microseconds later, inside the same login. The
// stage is what connects the two. Entries are consumed on use, expire quickly,
// and are keyed by the case-folded player name - the same field BDS fills into
// PlayerAuthenticationInfo.xbox_live_name, so the hook can find them.
#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace xuidforward {

struct StagedIdentity {
    std::string name;
    std::string xuid;
    std::string self_signed_id;
    std::chrono::steady_clock::time_point expires{};
};

class IdentityStage {
public:
    void put(const StagedIdentity &identity, int ttl_seconds)
    {
        std::lock_guard lock(mutex_);
        sweep_locked();
        StagedIdentity entry = identity;
        entry.expires = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_seconds);
        entries_[normalize(identity.name)] = std::move(entry);
    }

    // Consume-on-use: a staged identity can only ever justify one injection.
    std::optional<StagedIdentity> take(const std::string &name)
    {
        std::lock_guard lock(mutex_);
        sweep_locked();
        const auto it = entries_.find(normalize(name));
        if (it == entries_.end()) {
            return std::nullopt;
        }
        auto entry = it->second;
        entries_.erase(it);
        return entry;
    }

    // Drop everything pending. Called when a login arrives from outside this machine, so
    // that login can never pick up an identity staged for a relayed one.
    void clear()
    {
        std::lock_guard lock(mutex_);
        entries_.clear();
    }

    // Look without consuming - for diagnostics.
    std::optional<StagedIdentity> peek(const std::string &name)
    {
        std::lock_guard lock(mutex_);
        const auto it = entries_.find(normalize(name));
        if (it == entries_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    [[nodiscard]] std::size_t size()
    {
        std::lock_guard lock(mutex_);
        sweep_locked();
        return entries_.size();
    }

    // The names currently staged, for diagnostics (the status command and the
    // "staged but the login's name does not match" warning).
    std::string staged_names()
    {
        std::lock_guard lock(mutex_);
        sweep_locked();
        std::string out;
        for (const auto &entry : entries_) {
            if (!out.empty()) {
                out += ",";
            }
            out += entry.first;
        }
        return out;
    }

    static std::string normalize(const std::string &name)
    {
        std::string out;
        out.reserve(name.size());
        for (const char c : name) {
            out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
        }
        return out;
    }

private:
    void sweep_locked()
    {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->second.expires <= now) {
                it = entries_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    std::mutex mutex_;
    std::unordered_map<std::string, StagedIdentity> entries_;
};

IdentityStage &identity_stage();

}  // namespace xuidforward
