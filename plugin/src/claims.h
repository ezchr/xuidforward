// xuidforward - read the identity a relayed login already carries.
//
// A nether2rak (n2r) relay login is a Bedrock "offline" login: the client-data
// JWT is signed by the relay's own throwaway key, but it still carries the real
// player identity as claims, because the relay authenticated the player against
// Xbox Live at its own front door. BDS throws the XUID away for self-signed
// (AuthenticationType 2) logins; this header is how we get it back.
//
// Nothing here verifies a signature - we cannot, the signing key belongs to the
// relay - and nothing here is trusted on its own. The claims are only used
// after claims::self_signed_id_matches_xuid() confirms the login is internally
// consistent with the derivation the relay uses.
#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "mini_json.h"

namespace xuidforward::claims {

inline int base64url_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-' || c == '+') {
        return 62;
    }
    if (c == '_' || c == '/') {
        return 63;
    }
    return -1;
}

inline std::optional<std::string> base64url_decode(std::string_view text)
{
    std::string out;
    out.reserve(text.size() * 3 / 4 + 3);
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        if (c == '=' || c == '\n' || c == '\r') {
            continue;
        }
        const int value = base64url_value(c);
        if (value < 0) {
            return std::nullopt;
        }
        buffer = (buffer << 6) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

struct Identity {
    std::string name;          // ThirdPartyName
    std::string xuid;          // XUID claim
    std::string self_signed_id;  // SelfSignedId claim
    bool has_self_signed_id{false};
};

// Extract identity claims out of a decoded client-data JSON document.
inline Identity identity_from_client_data(const std::string &json)
{
    const auto values = parse_flat_json(json);
    Identity identity;
    if (const auto it = values.find("ThirdPartyName"); it != values.end()) {
        identity.name = it->second;
    }
    if (const auto it = values.find("XUID"); it != values.end()) {
        identity.xuid = it->second;
    }
    if (const auto it = values.find("SelfSignedId"); it != values.end()) {
        identity.self_signed_id = it->second;
        identity.has_self_signed_id = !identity.self_signed_id.empty();
    }
    return identity;
}

// A Bedrock Login packet payload is JSON: {"Certificate":"...","Token":"<jwt>"}.
// Older/other clients may hand us the JWT directly, so accept both shapes.
inline std::optional<std::string> client_data_token(std::string_view payload)
{
    const std::string text(payload);
    if (const auto values = parse_flat_json(text); !values.empty()) {
        if (const auto it = values.find("Token"); it != values.end() && !it->second.empty()) {
            return it->second;
        }
        if (values.find("XUID") != values.end() || values.find("ThirdPartyName") != values.end()) {
            return text;  // the payload itself is the client-data document
        }
    }
    return std::nullopt;
}

// Decode the payload segment of a JWT. Returns the raw JSON claims document.
inline std::optional<std::string> jwt_payload_json(std::string_view token)
{
    const auto first = token.find('.');
    if (first == std::string_view::npos) {
        return std::nullopt;
    }
    const auto second = token.find('.', first + 1);
    const auto segment = second == std::string_view::npos ? token.substr(first + 1)
                                                          : token.substr(first + 1, second - first - 1);
    return base64url_decode(segment);
}

// Convenience: raw Login payload -> identity claims.
inline std::optional<Identity> identity_from_login_payload(std::string_view payload)
{
    const auto token = client_data_token(payload);
    if (!token) {
        return std::nullopt;
    }
    const auto json = jwt_payload_json(*token);
    if (!json) {
        return std::nullopt;
    }
    return identity_from_client_data(*json);
}

}  // namespace xuidforward::claims
