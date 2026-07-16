#pragma once

#include <string>

namespace webhawk::models
{
struct UserSession
{
    int id{};
    int userId{};
    std::string tokenHash;
    std::string ipAddress;
    std::string createdAt;
    std::string expiresAt;
    bool isActive{};
};
}