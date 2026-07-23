#pragma once

namespace webhawk::security
{
struct RateLimitPolicyDecision
{
    bool blocked{};
    int remainingRequests{};
};

class RateLimitPolicy
{
public:
    static RateLimitPolicyDecision evaluate(
        int requestCount,
        int requestLimit,
        bool currentlyBlocked
    );
};
}