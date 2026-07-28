#pragma once

#include "models/SecurityLog.h"

#include <json/json.h>
#include <string>
#include <vector>

namespace webhawk::repositories
{
struct SecurityLogQuery
{
    std::string attackType;
    int blockedFilter{-1};
    int backendId{};
    int page{1};
    int pageSize{20};
};

class SecurityLogRepository
{
public:
    static int countSecurityLogs();

    static webhawk::models::SecurityLog createLog(
        int backendId,
        const std::string& ipAddress,
        const std::string& method,
        const std::string& endpoint,
        const std::string& attackType,
        bool isBlocked,
        const Json::Value& requestData
    );

    static std::vector<
        webhawk::models::SecurityLog
    >
    findByUserId(
        int userId,
        const SecurityLogQuery& query
    );

    static long long countByUserId(
        int userId,
        const SecurityLogQuery& query
    );
};
}