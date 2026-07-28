#pragma once

#include <string>
#include <vector>

namespace webhawk::models
{
struct AnalyticsSummary
{
    long long totalScanned{};
    long long totalBlocked{};
    long long totalAllowed{};
    double blockRate{};
};

struct AttackTypeCount
{
    std::string attackType;
    long long count{};
};

struct AttackTimelinePoint
{
    std::string date;
    long long totalRequests{};
    long long blockedRequests{};
};
}