#include "security/RateLimitPolicy.h"

#include <algorithm>

using namespace webhawk::security;

RateLimitPolicyDecision RateLimitPolicy::evaluate(
    int requestCount,
    int requestLimit,
    bool currentlyBlocked
)
{
    const int safeLimit =
        std::max(1, requestLimit);

    const int safeCount =
        std::max(0, requestCount);

    RateLimitPolicyDecision decision;

    decision.blocked =
        currentlyBlocked
        || safeCount > safeLimit;

    decision.remainingRequests = std::max(
        safeLimit - safeCount,
        0
    );

    return decision;
}
