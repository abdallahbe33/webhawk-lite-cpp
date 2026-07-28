#include "services/SecurityLogService.h"

#include "security/AuthMiddleware.h"

using namespace webhawk::services;

SecurityLogListResult
SecurityLogService::getLogs(
    const std::string& authorizationHeader,
    const webhawk::repositories::
        SecurityLogQuery& query
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                authorizationHeader
            );

    if (!authentication.success)
    {
        return {
            false,
            authentication.statusCode,
            authentication.message
        };
    }

    if (
        query.page < 1
        || query.pageSize < 1
        || query.pageSize > 100
    )
    {
        return {
            false,
            400,
            "page must be positive and "
            "page_size must be between 1 and 100"
        };
    }

    if (
        query.blockedFilter < -1
        || query.blockedFilter > 1
    )
    {
        return {
            false,
            400,
            "blocked filter is invalid"
        };
    }

    SecurityLogListResult result;

    result.success = true;
    result.statusCode = 200;

    result.message =
        "Security logs loaded successfully";

    result.logs =
        webhawk::repositories::
            SecurityLogRepository::
                findByUserId(
                    authentication.context.userId,
                    query
                );

    result.total =
        webhawk::repositories::
            SecurityLogRepository::
                countByUserId(
                    authentication.context.userId,
                    query
                );

    result.page = query.page;
    result.pageSize = query.pageSize;

    return result;
}