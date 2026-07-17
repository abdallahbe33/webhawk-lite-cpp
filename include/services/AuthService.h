#pragma once

#include "models/User.h"
#include "models/UserSession.h"

#include <string>
#include <vector>

namespace webhawk::services
{
struct ServiceResult
{
    bool success{};
    int statusCode{};
    std::string message;
    webhawk::models::User user;
};

struct LoginResult
{
    bool success{};
    int statusCode{};
    std::string message;
    webhawk::models::User user;
    std::string accessToken;
    std::string tokenType;
    std::string expiresAt;
};

struct SessionListResult
{
    bool success{};
    int statusCode{};
    std::string message;
    std::vector<webhawk::models::UserSession> sessions;
};

struct LogoutResult
{
    bool success{};
    int statusCode{};
    std::string message;
};

class AuthService
{
public:
    static ServiceResult registerUser(
        const std::string& name,
        const std::string& email,
        const std::string& password
    );

    static LoginResult login(
        const std::string& email,
        const std::string& password,
        const std::string& ipAddress
    );

    static SessionListResult getActiveSessions(
        const std::string& authorizationHeader
    );

    static LogoutResult logout(
        const std::string& authorizationHeader
    );

private:
    static bool isValidEmail(
        const std::string& email
    );

    static std::string trim(
        const std::string& value
    );

    static std::string toLower(
        const std::string& value
    );

    static std::string formatTimestamp(
        std::int64_t unixTimestamp
    );
};
}
