#include "xuid_forward_plugin.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include "claims.h"
#include "mini_json.h"
#include "stage.h"
#include "uuid5.h"

namespace xuidforward {
namespace {

// Bedrock packet id for Login. Only this packet is ever inspected.
constexpr int kLoginPacketId = 0x01;

std::string join_path(const std::string &dir, const char *name)
{
    if (dir.empty()) {
        return name;
    }
    return (std::filesystem::path(dir) / name).string();
}

}  // namespace

void XuidForwardPlugin::onLoad()
{
    auto &logger = getLogger();
    logger.info("xuidforward loading - restoring real XUIDs on relayed Bedrock logins");

    std::string data_dir;
    try {
        data_dir = getDataFolder().string();
    }
    catch (...) {
        data_dir.clear();
    }
    config_path_ = join_path(data_dir, "config.json");
    loadConfig();
    writeDefaultConfig(config_path_);

    profile_ = builtin_profile();
    if (!settings_.profile_path.empty()) {
        std::string error;
        if (auto loaded = load_profile(settings_.profile_path, error)) {
            profile_ = *loaded;
            logger.info("profile loaded from " + settings_.profile_path + " (BDS " + profile_.bds_version + ")");
        }
        else {
            logger.warning("could not load profile: " + error + " - using the built-in one");
        }
    }

    inject_config_ = InjectConfig{};
    inject_config_.profile = profile_;
    inject_config_.enabled = settings_.enabled;
    inject_config_.dry_run = settings_.dry_run;
    inject_config_.require_self_signed_id_match = settings_.require_self_signed_id_match;
    inject_config_.require_digit_xuid = settings_.require_digit_xuid;
    inject_config_.stage_ttl_seconds = settings_.stage_ttl_seconds;
    inject_config_.namespace_text = settings_.namespace_uuid;
    inject_config_.plugin_dir = data_dir;

    if (!parse_uuid(settings_.namespace_uuid, namespace_bytes_)) {
        logger.warning("namespace_uuid '" + settings_.namespace_uuid +
                       "' is not a valid UUID - relays using a different namespace will not be trusted");
    }
    inject_config_.namespace_uuid = namespace_bytes_;

    if (!inject_config_.layout.detect()) {
        logger.error("could not determine the libc++ std::string layout of this build - "
                     "no hook will be installed (nothing is patched)");
        settings_.enabled = false;
    }
    inject_config_.enabled = settings_.enabled;
}

void XuidForwardPlugin::onEnable()
{
    auto &logger = getLogger();
    registerEvent(&XuidForwardPlugin::onPacketReceive, *this);

    if (!settings_.enabled) {
        logger.warning("disabled by configuration - no hook installed, logins are untouched");
        return;
    }

    const auto base = main_image_base();
    if (base == 0) {
        logger.error("could not locate the BDS image in this process - nothing patched");
        return;
    }

    inject_configure(inject_config_);

    std::string error;
    if (!hook_.install(base, profile_, &inject_entry, error)) {
        logger.error("hook not installed: " + error);
        logger.error("this is the safe outcome - the server keeps running with BDS's stock behaviour");
        return;
    }
    hook_ready_ = true;

    std::ostringstream message;
    message << "hook installed: site=0x" << std::hex << hook_.site_address() << " relay=0x"
            << hook_.relay_address() << std::dec << " relay_bytes=" << hook_.relay_bytes().size();
    logger.info(message.str());
    logger.info(std::string("register contract: ") + relay_register_contract());
    if (settings_.dry_run) {
        logger.warning("DRY RUN - the hook is active and logs what it finds, but no XUID is written. "
                       "Set \"dry_run\": false in config.json once a test join looks correct.");
    }
    else {
        logger.info("relayed logins will be rewritten to carry the player's real XUID");
    }
}

void XuidForwardPlugin::onDisable()
{
    if (hook_ready_) {
        hook_.remove();
        hook_ready_ = false;
        getLogger().info("hook removed - BDS is back to stock behaviour");
    }
}

void XuidForwardPlugin::onPacketReceive(endstone::PacketReceiveEvent &event)
{
    if (!settings_.enabled || event.getPacketId() != kLoginPacketId) {
        return;
    }
    const auto identity = claims::identity_from_login_payload(event.getPayload());
    if (!identity) {
        return;
    }
    if (identity->name.empty() || identity->xuid.empty()) {
        return;  // a native/Xbox login: BDS already has the real identity
    }
    if (settings_.require_self_signed_id_match) {
        if (!identity->has_self_signed_id) {
            getLogger().warning("login for " + identity->name +
                                " claims a XUID but carries no SelfSignedId - not staging it");
            return;
        }
        const auto expected = uuid5(namespace_bytes_, identity->xuid);
        if (IdentityStage::normalize(expected) != IdentityStage::normalize(identity->self_signed_id)) {
            getLogger().warning("login for " + identity->name + " claims xuid " + identity->xuid +
                                " but its SelfSignedId (" + identity->self_signed_id +
                                ") is not the relay's derivation of it - not staging it");
            return;
        }
    }

    StagedIdentity staged;
    staged.name = identity->name;
    staged.xuid = identity->xuid;
    staged.self_signed_id = identity->self_signed_id;
    identity_stage().put(staged, settings_.stage_ttl_seconds);
    getLogger().info("staged relayed login: " + identity->name + " xuid=" + identity->xuid);
}

std::string XuidForwardPlugin::status() const
{
    if (!hook_ready_) {
        return "no hook installed";
    }
    const auto stats = inject_stats_snapshot();
    std::ostringstream out;
    out << "hook active" << (settings_.dry_run ? " (dry run)" : "") << "; calls=" << stats.calls
        << " injected=" << stats.injected << " would_inject=" << stats.would_inject
        << " not_engaged=" << stats.not_engaged << " name_unreadable=" << stats.name_unreadable
        << " name_not_staged=" << stats.name_not_staged << " write_refused=" << stats.write_refused;
    return out.str();
}

void XuidForwardPlugin::loadConfig()
{
    std::string text;
    std::unordered_map<std::string, std::string> values;
    if (read_file(config_path_, text)) {
        values = parse_flat_json(text);
    }
    const auto flag = [&](const char *key, bool fallback) {
        const auto it = values.find(key);
        return it == values.end() ? fallback : parse_bool(it->second, fallback);
    };
    const auto number = [&](const char *key, int fallback) {
        const auto it = values.find(key);
        if (it == values.end()) {
            return fallback;
        }
        const auto parsed = parse_u64(it->second);
        return parsed ? static_cast<int>(*parsed) : fallback;
    };
    const auto text_of = [&](const char *key, const std::string &fallback) {
        const auto it = values.find(key);
        return it == values.end() ? fallback : it->second;
    };

    settings_.enabled = flag("enabled", settings_.enabled);
    settings_.dry_run = flag("dry_run", settings_.dry_run);
    settings_.require_self_signed_id_match =
        flag("require_self_signed_id_match", settings_.require_self_signed_id_match);
    settings_.require_digit_xuid = flag("require_digit_xuid", settings_.require_digit_xuid);
    settings_.stage_ttl_seconds = number("stage_ttl_seconds", settings_.stage_ttl_seconds);
    settings_.profile_path = text_of("profile", settings_.profile_path);
    settings_.namespace_uuid = text_of("namespace_uuid", settings_.namespace_uuid);
    settings_.log_file = text_of("log_file", settings_.log_file);
    if (settings_.stage_ttl_seconds < 5 || settings_.stage_ttl_seconds > 600) {
        settings_.stage_ttl_seconds = 30;
    }
}

void XuidForwardPlugin::writeDefaultConfig(const std::string &path) const
{
    std::string existing;
    if (read_file(path, existing)) {
        return;
    }
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return;
    }
    file << R"({
  "_comment": "xuidforward - restore the real XUID on relayed (self-signed) logins. dry_run only logs; leave it on until a test join looks right.",
  "enabled": true,
  "dry_run": true,
  "namespace_uuid": "a3e78ee7-823a-4cb5-9fe0-532b54ccc20d",
  "_namespace_uuid_comment": "Must match selfSignedIDNamespace in the relay (n2rpush/proxy/self_signed_id.go). A login is only trusted when SelfSignedId == uuid5(namespace_uuid, XUID).",
  "require_self_signed_id_match": true,
  "require_digit_xuid": true,
  "stage_ttl_seconds": 30,
  "profile": ""
}
)";
}

}  // namespace xuidforward

ENDSTONE_PLUGIN("xuidforward", "1.0.0", xuidforward::XuidForwardPlugin)
{
    description = "Restores the real XUID on relayed (self-signed) Bedrock logins so a native BDS "
                  "serves the player's own save data instead of a relay-specific record.";
    authors = {"Cline, for the nether2rak relay deployment"};
}
