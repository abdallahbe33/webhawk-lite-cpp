#include "security/RateLimiter.h"

#include "config/AppConfig.h"
#include "repositories/RateLimitRepository.h"
#include "security/RateLimitPolicy.h"

#include <stdexcept>

using namespace webhawk::security;

Json::Value RateLimitCheckResult::toJson() const
{
    Json::Value body;

    body["allowed"] = allowed;

    body["attack_type"] =
        allowed ? "NONE" : "RATE_LIMIT";

    body["message"] = message;

    Json::Value details;

    details["backend_id"] = state.backendId;
    details["ip_address"] = state.ipAddress;
    details["endpoint"] = state.endpoint;
    details["request_count"] = state.requestCount;
    details["request_limit"] = requestLimit;

    details["remaining_requests"] =
        state.remainingRequests;

    details["window_seconds"] = windowSeconds;
    details["block_seconds"] = blockSeconds;
    details["window_start"] = state.windowStart;
    details["is_blocked"] = state.isBlocked;

    details["retry_after_seconds"] =
        state.retryAfterSeconds;

    if (!state.blockedUntil.empty())
    {
        details["blocked_until"] =
            state.blockedUntil;
    }
    else
    {
        details["blocked_until"] =
            Json::nullValue;
    }

    body["rate_limit"] = details;

    return body;
}

RateLimitCheckResult RateLimiter::check(
    int backendId,
    const std::string& ipAddress,
    const std::string& endpoint
)
{
    if (backendId <= 0)
    {
        throw std::invalid_argument(
            "backend_id must be positive"
        );
    }

    if (
        ipAddress.empty()
        || ipAddress.size() > 45
    )
    {
        throw std::invalid_argument(
            "A valid IP address is required"
        );
    }

    if (
        endpoint.empty()
        || endpoint.size() > 2048
    )
    {
        throw std::invalid_argument(
            "A valid endpoint is required"
        );
    }

    const int requestLimit =
        webhawk::config::AppConfig::
            rateLimitRequests();

    const int windowSeconds =
        webhawk::config::AppConfig::
            rateLimitWindowSeconds();

    const int blockSeconds =
        webhawk::config::AppConfig::
            rateLimitBlockSeconds();

    auto state =
        webhawk::repositories::
            RateLimitRepository::consumeRequest(
                backendId,
                ipAddress,
                endpoint,
                requestLimit,
                windowSeconds,
                blockSeconds
            );

    const auto policy =
        RateLimitPolicy::evaluate(
            state.requestCount,
            requestLimit,
            state.isBlocked
        );

    state.remainingRequests =
        policy.remainingRequests;

    RateLimitCheckResult result;

    result.allowed = !policy.blocked;

    result.statusCode =
        result.allowed ? 200 : 429;

    result.message = result.allowed
        ? "Request is within the rate limit"
        : "Too many requests. Try again later";

    result.requestLimit = requestLimit;
    result.windowSeconds = windowSeconds;
    result.blockSeconds = blockSeconds;
    result.state = state;

    return result;
}