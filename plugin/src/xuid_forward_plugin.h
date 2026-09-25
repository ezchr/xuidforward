// xuidforward - an Endstone plugin that makes a native BDS accept the real XUID
// on relayed (self-signed) logins.
//
// Why this exists
// ---------------
// nether2rak relays players into a native Bedrock Dedicated Server. It cannot
// forward the player's original signed login chain, because the backend
// encrypts to the public key inside whatever chain it receives - so the relay
// mints its own keypair and sends a self-signed ("AuthenticationType 2") login
// carrying the real identity as JWT claims.
//
// Native BDS throws that XUID away for self-signed logins and keys the player's
// on-disk record by ClientData.SelfSignedId instead. The relay works around that
// by deriving SelfSignedId deterministically from the XUID (stable record, no
// more empty save every reconnect) - but the record still is not the player's
// real, XUID-keyed record, so relayed players never see their existing data,
// and their inventory lives in a parallel save that a direct/native join does
// not use.
//
// This plugin closes that last gap: when BDS has finished validating a relayed
// login, it rewrites the XUID in the authentication result before BDS selects
// player storage. BDS then behaves exactly as if the player had logged in
// natively - same record, one save, whether they arrived through the relay or
// not.
//
// Safety model
// ------------
//   * Only logins whose SelfSignedId equals uuid5(namespace, XUID) are staged,
//     i.e. logins produced by the relay that owns that namespace.
//   * Only the staged player's own result is touched, matched by name, consumed
//     once, within a short window.
//   * The hook refuses to install if the running BDS build does not match the
//     profile byte for byte.
//   * dry_run (the default) does everything except the write, and logs exactly
//     what it would change.
#pragma once

#include <array>
#include <memory>
#include <optional>
#include <string>

#include <endstone/endstone.hpp>

#include "hook.h"
#include "inject.h"
#include "profile.h"

namespace xuidforward {

class XuidForwardPlugin : public endstone::Plugin {
public:
    void onLoad() override;
    void onEnable() override;
    void onDisable() override;

    // PacketReceiveEvent: stage the identity of a relayed login before BDS turns
    // it into a PlayerAuthenticationInfo.
    void onPacketReceive(endstone::PacketReceiveEvent &event);

    [[nodiscard]] std::string status() const;

private:
    void loadConfig();
    void writeDefaultConfig(const std::string &path) const;

    struct Settings {
        bool enabled{true};
        bool dry_run{true};
        bool require_self_signed_id_match{true};
        bool require_digit_xuid{true};
        int stage_ttl_seconds{30};
        std::string profile_path;
        std::string namespace_uuid{"a3e78ee7-823a-4cb5-9fe0-532b54ccc20d"};
        std::string log_file;
    };

    Settings settings_;
    Profile profile_;
    InjectConfig inject_config_;
    SiteHook hook_;
    std::array<std::uint8_t, 16> namespace_bytes_{};
    std::string config_path_;
    bool hook_ready_{false};
};

}  // namespace xuidforward
