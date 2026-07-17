#pragma once

#include <json/json.h>
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

    Json::Value toJson() const
    {
        Json::Value value;

        value["id"] = id;
        value["user_id"] = userId;
        value["ip_address"] = ipAddress;
        value["created_at"] = createdAt;
        value["expires_at"] = expiresAt;
        value["is_active"] = isActive;

        return value;
    }
};
}
