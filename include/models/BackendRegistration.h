#pragma once

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
};
}