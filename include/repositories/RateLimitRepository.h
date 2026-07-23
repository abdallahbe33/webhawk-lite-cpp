#pragma once

#include "models/RateLimit.h"

#include <string>

namespace webhawk::repositories
{
class RateLimitRepository
{
public:
    static int countRateLimitRecords();

    static webhawk::models::RateLimit consumeRequest(
        int backendId,
        const std::string& ipAddress,
        const std::string& endpoint,
        int requestLimit,
        int windowSeconds,
        int blockSeconds
    );
};
}