// xuidforward - the C ABI the Python plugin talks to.
//
// Why a shim instead of a native C++ plugin: Endstone ships no C++ SDK artifact
// (the release bundles contain only a wheel + start.sh) and libendstone_runtime.so
// exports essentially none of the endstone:: C++ API, so a native plugin would mean
// rebuilding Endstone from source with conan - replacing a working install to gain
// nothing that matters here. The one thing that *must* be native is the code patch
// inside BDS's login path; everything else (config, packet handling) is happy in the
// Python API, which does expose PacketReceiveEvent.
//
// So: this .so is loaded into the BDS process by the Python plugin via ctypes and
// exposes a handful of calls. No Endstone headers, no C++ ABI coupling - it only
// needs the BDS image and the profile.
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#include "hook.h"
#include "inject.h"
#include "profile.h"
#include "stage.h"
#include "uuid5.h"

namespace {

std::mutex g_mutex;
xuidforward::SiteHook g_hook;
std::string g_error;
std::string g_status = "not installed";
std::array<std::uint8_t, 16> g_namespace{};
bool g_ready = false;

void set_error(const std::string &message)
{
    std::lock_guard lock(g_mutex);
    g_error = message;
}

}  // namespace

extern "C" {

const char *xf_version(void)
{
    return "xuidforward-shim 1.0.1";
}

const char *xf_register_contract(void)
{
    return xuidforward::relay_register_contract();
}

const char *xf_last_error(void)
{
    std::lock_guard lock(g_mutex);
    return g_error.c_str();
}

// Set the namespace used to validate SelfSignedId against XUID. Normally
// configured by xf_install(); exposed so the standalone smoke test can exercise
// the positive staging path without a running server.
int xf_set_namespace(const char *namespace_uuid)
{
    std::lock_guard lock(g_mutex);
    if (namespace_uuid == nullptr || !xuidforward::parse_uuid(namespace_uuid, g_namespace)) {
        g_error = "namespace_uuid is not a valid UUID";
        return 1;
    }
    return 0;
}

// Diagnostic: work out the libc++ std::string layout in this process. This is the
// step that crashed the first build (it dereferenced an unvalidated pointer), so it
// is now reachable without a live server.
int xf_layout_probe(char *out, int out_size)
{
    xuidforward::StringLayout layout;
    const bool ok = layout.detect();
    if (out != nullptr && out_size > 0) {
        std::snprintf(out, static_cast<std::size_t>(out_size), "%s: %s | %s",
                      ok ? "detected" : "NOT detected", layout.describe().c_str(),
                      xuidforward::StringLayout::probe_dump().c_str());
    }
    return ok ? 0 : 1;
}

// Exists so the plugin can prove the shim loaded and that the profile matches this
// BDS build before it installs anything.
int xf_self_check(const char *profile_path, char *out, int out_size)
{
    xuidforward::Profile profile = xuidforward::builtin_profile();
    if (profile_path != nullptr && profile_path[0] != '\0') {
        std::string error;
        const auto loaded = xuidforward::load_profile(profile_path, error);
        if (!loaded) {
            if (out != nullptr && out_size > 0) {
                std::snprintf(out, static_cast<std::size_t>(out_size), "%s", error.c_str());
            }
            return 1;
        }
        profile = *loaded;
    }
    const auto base = xuidforward::main_image_base();
    std::string error;
    const bool ok = base != 0 && xuidforward::verify_site(profile, base, error);
    if (out != nullptr && out_size > 0) {
        const std::string message = ok ? ("profile valid: BDS " + profile.bds_version)
                                       : (base == 0 ? std::string("no BDS image base") : error);
        std::snprintf(out, static_cast<std::size_t>(out_size), "%s", message.c_str());
    }
    return ok ? 0 : 2;
}

// Install the hook. Returns 0 on success; on failure xf_last_error() says why and
// nothing has been patched.
int xf_install(const char *profile_path, int dry_run, const char *namespace_uuid, int stage_ttl_seconds,
               int require_self_signed_id_match, int require_digit_xuid)
{
    std::lock_guard lock(g_mutex);
    g_error.clear();

    xuidforward::Profile profile = xuidforward::builtin_profile();
    if (profile_path != nullptr && profile_path[0] != '\0') {
        std::string error;
        const auto loaded = xuidforward::load_profile(profile_path, error);
        if (!loaded) {
            g_error = error;
            return 1;
        }
        profile = *loaded;
    }

    xuidforward::InjectConfig config;
    config.profile = profile;
    config.enabled = true;
    config.dry_run = dry_run != 0;
    config.require_self_signed_id_match = require_self_signed_id_match != 0;
    config.require_digit_xuid = require_digit_xuid != 0;
    config.stage_ttl_seconds = stage_ttl_seconds <= 0 ? 30 : stage_ttl_seconds;
    config.namespace_text = namespace_uuid == nullptr ? "" : namespace_uuid;
    if (!xuidforward::parse_uuid(config.namespace_text, g_namespace)) {
        g_error = "namespace_uuid is not a valid UUID";
        return 2;
    }
    config.namespace_uuid = g_namespace;
    if (!config.layout.detect()) {
        g_error = "could not determine the libc++ std::string layout of this build";
        return 3;
    }
    xuidforward::inject_configure(config);

    const auto base = xuidforward::main_image_base();
    if (base == 0) {
        g_error = "could not locate the BDS image in this process";
        return 4;
    }
    std::string error;
    if (!g_hook.install(base, profile, &xuidforward::inject_entry, error)) {
        g_error = error;
        return 5;
    }

    g_ready = true;
    return 0;
}

int xf_uninstall(void)
{
    std::lock_guard lock(g_mutex);
    // Stop rewriting first - then report the hook as removed. The code patch itself
    // stays in place on purpose: see SiteHook::remove() for why unmapping mid-login
    // would crash BDS.
    xuidforward::inject_enable(false);
    if (g_ready) {
        g_hook.remove();
        g_ready = false;
    }
    g_status = "not installed";
    return 0;
}

// Stage an identity for the login that is about to be validated. Returns 0 if the
// identity is consistent with the relay's derivation, non-zero if it is not (and
// nothing was staged).
int xf_stage(const char *name, const char *xuid, const char *self_signed_id)
{
    if (name == nullptr || xuid == nullptr || name[0] == '\0' || xuid[0] == '\0') {
        return 1;
    }
    const std::string self_id = self_signed_id == nullptr ? "" : self_signed_id;
    if (xuidforward::inject_config().require_self_signed_id_match) {
        if (self_id.empty()) {
            set_error("login carries no SelfSignedId");
            return 1;
        }
        const auto expected = xuidforward::uuid5(g_namespace, xuid);
        if (xuidforward::IdentityStage::normalize(expected) !=
            xuidforward::IdentityStage::normalize(self_id)) {
            set_error(std::string("SelfSignedId ") + self_id + " is not uuid5(namespace, " + xuid + ")");
            return 1;
        }
    }
    xuidforward::StagedIdentity staged;
    staged.name = name;
    staged.xuid = xuid;
    staged.self_signed_id = self_id;
    xuidforward::identity_stage().put(staged, xuidforward::inject_config().stage_ttl_seconds);
    return 0;
}

// Drop every pending identity. The plugin calls this for each login that arrives from
// outside this machine, before BDS processes it, so such a login can never be handed an
// identity that was staged for a relayed one.
int xf_clear_stage(void)
{
    xuidforward::identity_stage().clear();
    return 0;
}

// Diagnostic string for the plugin log.
const char *xf_status(void)
{
    std::lock_guard lock(g_mutex);
    const auto stats = xuidforward::inject_stats_snapshot();
    g_status = g_ready ? "installed" : "not installed";
    g_status += "; staged_now=" + std::to_string(xuidforward::identity_stage().size());
    g_status += " staged=[" + xuidforward::identity_stage().staged_names() + "]";
    g_status += " calls=" + std::to_string(stats.calls);
    g_status += " injected=" + std::to_string(stats.injected);
    g_status += " would_inject=" + std::to_string(stats.would_inject);
    g_status += " not_engaged=" + std::to_string(stats.not_engaged);
    g_status += " name_unreadable=" + std::to_string(stats.name_unreadable);
    g_status += " name_not_staged=" + std::to_string(stats.name_not_staged);
    g_status += " write_refused=" + std::to_string(stats.write_refused);
    g_status += " xuid_present=" + std::to_string(stats.xuid_present);
    return g_status.c_str();
}

}  // extern "C"
