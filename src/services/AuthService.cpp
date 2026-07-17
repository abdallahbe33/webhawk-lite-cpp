#include "services/AuthService.h"

#include "repositories/UserRepository.h"
#include "repositories/SessionRepository.h"
#include "security/AuthMiddleware.h"
#include "security/JwtService.h"
#include "security/PasswordHasher.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <regex>
#include <sstream>

using namespace webhawk::services;

std::string AuthService::trim(
    const std::string& value
)
{
    const auto first = value.find_first_not_of(" \t\n\r");

    if (first == std::string::npos)
    {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\n\r");

    return value.substr(
        first,
        last - first + 1
    );
}

std::string AuthService::toLower(
    const std::string& value
)
{
    std::string lowered = value;

    std::transform(
        lowered.begin(),
        lowered.end(),
        lowered.begin(),
        [](unsigned char character)
        {
            return static_cast<char>(
                std::tolower(character)
            );
        }
    );

    return lowered;
}

bool AuthService::isValidEmail(
    const std::string& email
)
{
    static const std::regex pattern(
        R"(^[^\s@]+@[^\s@]+\.[^\s@]+$)"
    );

    return std::regex_match(
        email,
        pattern
    );
}

ServiceResult AuthService::registerUser(
    const std::string& name,
    const std::string& email,
    const std::string& password
)
{
    const std::string cleanName = trim(name);
    const std::string cleanEmail = toLower(
        trim(email)
    );

    if (cleanName.empty())
    {
        return {
            false,
            400,
            "Name is required",
            {}
        };
    }

    if (!isValidEmail(cleanEmail))
    {
        return {
            false,
            400,
            "A valid email is required",
            {}
        };
    }

    if (password.size() < 8)
    {
        return {
            false,
            400,
            "Password must contain at least 8 characters",
            {}
        };
    }

    const auto existingUser =
        webhawk::repositories::UserRepository::findByEmail(
            cleanEmail
        );

    if (existingUser.has_value())
    {
        return {
            false,
            409,
            "Email is already registered",
            {}
        };
    }

    const std::string passwordHash =
        webhawk::security::PasswordHasher::hashPassword(
            password
        );

    const auto createdUser =
        webhawk::repositories::UserRepository::createUser(
            cleanName,
            cleanEmail,
            passwordHash
        );

    return {
        true,
        201,
        "User registered successfully",
        createdUser
    };
}

std::string AuthService::formatTimestamp(
    std::int64_t unixTimestamp
)
{
    const std::time_t time = static_cast<std::time_t>(
        unixTimestamp
    );

    std::tm utcTime{};

#ifdef _WIN32
    gmtime_s(&utcTime, &time);
#else
    gmtime_r(&time, &utcTime);
#endif

    std::ostringstream stream;
    stream << std::put_time(
        &utcTime,
        "%Y-%m-%dT%H:%M:%SZ"
    );

    return stream.str();
}

LoginResult AuthService::login(
    const std::string& email,
    const std::string& password,
    const std::string& ipAddress
)
{
    const std::string cleanEmail = toLower(
        trim(email)
    );

    if (cleanEmail.empty() || password.empty())
    {
        return {
            false,
            400,
            "Email and password are required",
            {},
            "",
            "",
            ""
        };
    }

    const auto user =
        webhawk::repositories::UserRepository::findByEmail(
            cleanEmail
        );

    if (
        !user.has_value()
        || !webhawk::security::PasswordHasher::verifyPassword(
            password,
            user->passwordHash
        )
    )
    {
        return {
            false,
            401,
            "Invalid email or password",
            {},
            "",
            "",
            ""
        };
    }

    const auto jwt =
        webhawk::security::JwtService::createToken(
            user->id
        );

    const std::string tokenHash =
        webhawk::security::JwtService::hashToken(
            jwt.token
        );

    webhawk::repositories::SessionRepository::createSession(
        user->id,
        tokenHash,
        ipAddress.empty() ? "unknown" : ipAddress,
        jwt.claims.expiresAt
    );

    return {
        true,
        200,
        "Login successful",
        user.value(),
        jwt.token,
        "Bearer",
        formatTimestamp(jwt.claims.expiresAt)
    };
}

SessionListResult AuthService::getActiveSessions(
    const std::string& authorizationHeader
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::authenticate(
            authorizationHeader
        );

    if (!authentication.success)
    {
        return {
            false,
            authentication.statusCode,
            authentication.message,
            {}
        };
    }

    const auto sessions =
        webhawk::repositories::SessionRepository::findActiveByUserId(
            authentication.context.userId
        );

    return {
        true,
        200,
        "Active sessions returned successfully",
        sessions
    };
}

LogoutResult AuthService::logout(
    const std::string& authorizationHeader
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::authenticate(
            authorizationHeader
        );

    if (!authentication.success)
    {
        return {
            false,
            authentication.statusCode,
            authentication.message
        };
    }

    const bool deactivated =
        webhawk::repositories::SessionRepository::deactivateByTokenHash(
            authentication.context.tokenHash
        );

    if (!deactivated)
    {
        return {
            false,
            401,
            "Session is already inactive"
        };
    }

    return {
        true,
        200,
        "Logout successful"
    };
}
