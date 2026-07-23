#pragma once

#include "models/RateLimit.h"

#include <json/json.h>
#include <string>

namespace webhawk::security
{
struct RateLimitCheckResult
{
    bool allowed{true};
    int statusCode{200};
    std::string message;
    int requestLimit{};
    int windowSeconds{};
    int blockSeconds{};
    webhawk::models::RateLimit state;

    Json::Value toJson() const;
};

class RateLimiter
{
public:
    static RateLimitCheckResult check(
        int backendId,
        const std::string& ipAddress,
        const std::string& endpoint
    );
};
}