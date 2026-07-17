#pragma once

#include "models/UserSession.h"
#include "security/JwtService.h"

#include <string>

namespace webhawk::security
{
struct AuthContext
{
    int userId{};
    std::string token;
    std::string tokenHash;
    JwtClaims claims;
    webhawk::models::UserSession session;
};

struct AuthenticationResult
{
    bool success{};
    int statusCode{};
    std::string message;
    AuthContext context;
};

class AuthMiddleware
{
public:
    static AuthenticationResult authenticate(
        const std::string& authorizationHeader
    );

private:
    static std::string extractBearerToken(
        const std::string& authorizationHeader
    );
};
}
