#pragma once

#include "models/SecurityLog.h"
#include "repositories/SecurityLogRepository.h"

#include <string>
#include <vector>

namespace webhawk::services
{
struct SecurityLogListResult
{
    bool success{};
    int statusCode{};
    std::string message;

    std::vector<
        webhawk::models::SecurityLog
    > logs;

    long long total{};
    int page{};
    int pageSize{};
};

class SecurityLogService
{
public:
    static SecurityLogListResult getLogs(
        const std::string& authorizationHeader,
        const webhawk::repositories::
            SecurityLogQuery& query
    );
};
}