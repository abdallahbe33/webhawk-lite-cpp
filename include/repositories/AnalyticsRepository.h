#pragma once

#include "models/Analytics.h"

#include <vector>

namespace webhawk::repositories
{
class AnalyticsRepository
{
public:
    static webhawk::models::
        AnalyticsSummary
    summaryForUser(
        int userId
    );

    static std::vector<
        webhawk::models::AttackTypeCount
    >
    attacksByTypeForUser(
        int userId
    );

    static std::vector<
        webhawk::models::AttackTimelinePoint
    >
    attacksOverTimeForUser(
        int userId,
        int days
    );
};
}