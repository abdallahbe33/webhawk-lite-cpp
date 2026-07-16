#pragma once

#include <string>

namespace webhawk::models
{
struct RateLimit
{
    int id{};
    int backendId{};
    std::string ipAddress;
    std::string endpoint;
    int requestCount{};
    std::string windowStart;
    std::string blockedUntil;
    bool isBlocked{};
};
}