#pragma once

#include <json/json.h>
#include <string>

namespace webhawk::models
{
struct User
{
    int id{};
    std::string name;
    std::string email;
    std::string passwordHash;
    std::string createdAt;
    std::string updatedAt;

    Json::Value toJson() const
    {
        Json::Value value;

        value["id"] = id;
        value["name"] = name;
        value["email"] = email;
        value["created_at"] = createdAt;
        value["updated_at"] = updatedAt;

        return value;
    }
};
}