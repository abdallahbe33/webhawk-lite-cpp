#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace webhawk::security
{
struct JwtClaims
{
    int userId{};
    std::string tokenId;
    std::int64_t issuedAt{};
    std::int64_t expiresAt{};
};

struct CreatedJwt
{
    std::string token;
    JwtClaims claims;
};

class JwtService
{
public:
    static CreatedJwt createToken(
        int userId
    );

    static std::optional<JwtClaims> validateToken(
        const std::string& token
    );

    static std::string hashToken(
        const std::string& token
    );

private:
    static std::string base64UrlEncode(
        const unsigned char* data,
        std::size_t length
    );

    static std::optional<std::string> base64UrlDecode(
        const std::string& value
    );

    static std::string sign(
        const std::string& value
    );

    static std::string generateTokenId();
    static std::string toHex(
        const unsigned char* data,
        std::size_t length
    );
};
}
