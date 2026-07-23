#include "security/RateLimitPolicy.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace
{
void require(
    bool condition,
    const std::string& message
)
{
    if (!condition)
    {
        std::cerr
            << "FAILED: "
            << message
            << '\n';

        std::exit(1);
    }
}
}

int main()
{
    using webhawk::security::RateLimitPolicy;

    const auto first =
        RateLimitPolicy::evaluate(
            1,
            100,
            false
        );

    require(
        !first.blocked,
        "First request should be allowed"
    );

    require(
        first.remainingRequests == 99,
        "Expected 99 remaining requests"
    );

    const auto lastAllowed =
        RateLimitPolicy::evaluate(
            100,
            100,
            false
        );

    require(
        !lastAllowed.blocked,
        "Request 100 should be allowed"
    );

    require(
        lastAllowed.remainingRequests == 0,
        "Expected no requests remaining"
    );

    const auto exceeded =
        RateLimitPolicy::evaluate(
            101,
            100,
            true
        );

    require(
        exceeded.blocked,
        "Request 101 should be blocked"
    );

    require(
        exceeded.remainingRequests == 0,
        "Blocked request has no remaining quota"
    );

    const auto activeBlock =
        RateLimitPolicy::evaluate(
            5,
            100,
            true
        );

    require(
        activeBlock.blocked,
        "An active block must remain blocked"
    );

    const auto invalidValues =
        RateLimitPolicy::evaluate(
            -1,
            0,
            false
        );

    require(
        !invalidValues.blocked,
        "Invalid values must be safely normalized"
    );

    require(
        invalidValues.remainingRequests == 1,
        "The minimum request limit must be one"
    );

    std::cout
        << "All rate limit policy tests passed\n";

    return 0;
}