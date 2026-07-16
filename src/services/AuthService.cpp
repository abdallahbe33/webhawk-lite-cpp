#include "services/AuthService.h"

#include "repositories/UserRepository.h"
#include "security/PasswordHasher.h"

#include <algorithm>
#include <cctype>
#include <regex>

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