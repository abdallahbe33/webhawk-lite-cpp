#pragma once

#include <json/json.h>
#include <string>

namespace webhawk::models
{
struct BackendRegistration
{
    int id{};
    int userId{};
    std::string serviceName;
    std::string targetUrl;
    std::string apiKey;
    bool isActive{};
    std::string createdAt;
    std::string updatedAt;

    Json::Value toJson() const
    {
        Json::Value value;

        value["id"] = id;
        value["user_id"] = userId;
        value["service_name"] = serviceName;
        value["target_url"] = targetUrl;
        value["api_key"] = apiKey;
        value["is_active"] = isActive;
        value["created_at"] = createdAt;
        value["updated_at"] = updatedAt;

        return value;
    }
};
}