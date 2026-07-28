#pragma once

#include <json/json.h>
#include <string>

namespace webhawk::services
{
struct AnalyticsResult
{
    bool success{};
    int statusCode{};
    std::string message;
    Json::Value data;
};

class AnalyticsService
{
public:
    static AnalyticsResult getSummary(
        const std::string& authorizationHeader
    );

    static AnalyticsResult getAttacksByType(
        const std::string& authorizationHeader
    );

    static AnalyticsResult getRecentAttacks(
        const std::string& authorizationHeader,
        int limit
    );

    static AnalyticsResult getAttacksOverTime(
        const std::string& authorizationHeader,
        int days
    );
};
}