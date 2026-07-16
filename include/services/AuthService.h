#pragma once

#include "models/User.h"

#include <string>

namespace webhawk::services
{
struct ServiceResult
{
    bool success{};
    int statusCode{};
    std::string message;
    webhawk::models::User user;
};

class AuthService
{
public:
    static ServiceResult registerUser(
        const std::string& name,
        const std::string& email,
        const std::string& password
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
};
}