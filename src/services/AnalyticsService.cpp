#include "services/AnalyticsService.h"

#include "repositories/AnalyticsRepository.h"
#include "repositories/SecurityLogRepository.h"
#include "security/AuthMiddleware.h"

using namespace webhawk::services;

namespace
{
AnalyticsResult authenticationError(
    const webhawk::security::
        AuthenticationResult& authentication
)
{
    return {
        false,
        authentication.statusCode,
        authentication.message,
        {}
    };
}
}

AnalyticsResult AnalyticsService::getSummary(
    const std::string& authorizationHeader
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                authorizationHeader
            );

    if (!authentication.success)
    {
        return authenticationError(
            authentication
        );
    }

    const auto summary =
        webhawk::repositories::
            AnalyticsRepository::
                summaryForUser(
                    authentication.context.userId
                );

    Json::Value data;

    data["total_scanned_requests"] =
        Json::Int64(
            summary.totalScanned
        );

    data["total_blocked_requests"] =
        Json::Int64(
            summary.totalBlocked
        );

    data["total_allowed_requests"] =
        Json::Int64(
            summary.totalAllowed
        );

    data["block_rate_percent"] =
        summary.blockRate;

    return {
        true,
        200,
        "Analytics summary loaded successfully",
        data
    };
}

AnalyticsResult
AnalyticsService::getAttacksByType(
    const std::string& authorizationHeader
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                authorizationHeader
            );

    if (!authentication.success)
    {
        return authenticationError(
            authentication
        );
    }

    const auto attacks =
        webhawk::repositories::
            AnalyticsRepository::
                attacksByTypeForUser(
                    authentication.context.userId
                );

    Json::Value items(
        Json::arrayValue
    );

    for (const auto& attack : attacks)
    {
        Json::Value item;

        item["attack_type"] =
            attack.attackType;

        item["count"] =
            Json::Int64(attack.count);

        items.append(item);
    }

    Json::Value data;
    data["attacks"] = items;

    return {
        true,
        200,
        "Attack statistics loaded successfully",
        data
    };
}

AnalyticsResult
AnalyticsService::getRecentAttacks(
    const std::string& authorizationHeader,
    int limit
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                authorizationHeader
            );

    if (!authentication.success)
    {
        return authenticationError(
            authentication
        );
    }

    if (limit < 1 || limit > 100)
    {
        return {
            false,
            400,
            "limit must be between 1 and 100",
            {}
        };
    }

    webhawk::repositories::
        SecurityLogQuery query;

    query.blockedFilter = 1;
    query.page = 1;
    query.pageSize = limit;

    const auto logs =
        webhawk::repositories::
            SecurityLogRepository::
                findByUserId(
                    authentication.context.userId,
                    query
                );

    Json::Value items(
        Json::arrayValue
    );

    for (const auto& log : logs)
    {
        items.append(log.toJson());
    }

    Json::Value data;

    data["count"] =
        Json::UInt64(logs.size());

    data["attacks"] = items;

    return {
        true,
        200,
        "Recent attacks loaded successfully",
        data
    };
}

AnalyticsResult
AnalyticsService::getAttacksOverTime(
    const std::string& authorizationHeader,
    int days
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                authorizationHeader
            );

    if (!authentication.success)
    {
        return authenticationError(
            authentication
        );
    }

    if (days < 1 || days > 90)
    {
        return {
            false,
            400,
            "days must be between 1 and 90",
            {}
        };
    }

    const auto timeline =
        webhawk::repositories::
            AnalyticsRepository::
                attacksOverTimeForUser(
                    authentication.context.userId,
                    days
                );

    Json::Value items(
        Json::arrayValue
    );

    for (const auto& point : timeline)
    {
        Json::Value item;

        item["date"] = point.date;

        item["total_requests"] =
            Json::Int64(
                point.totalRequests
            );

        item["blocked_requests"] =
            Json::Int64(
                point.blockedRequests
            );

        items.append(item);
    }

    Json::Value data;

    data["days"] = days;
    data["timeline"] = items;

    return {
        true,
        200,
        "Attack timeline loaded successfully",
        data
    };
}