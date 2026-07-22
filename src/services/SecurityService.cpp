#include "services/SecurityService.h"

#include "security/AuthMiddleware.h"
#include "security/RequestScanner.h"

using namespace webhawk::services;

namespace
{
SecurityScanResult runScan(
    const std::string& authorizationHeader,
    const Json::Value& requestData,
    bool sqlOnly
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::authenticate(
            authorizationHeader
        );

    if (!authentication.success)
    {
        return {
            false,
            authentication.statusCode,
            false,
            authentication.message,
            "",
            {}
        };
    }

    if (
        !requestData.isObject()
        || requestData.empty()
    )
    {
        return {
            false,
            400,
            false,
            "A non-empty JSON object is required",
            "",
            {}
        };
    }

    const auto scanResult = sqlOnly
        ? webhawk::security::RequestScanner::
            scanSqlInjection(requestData)
        : webhawk::security::RequestScanner::
            scan(requestData);

    if (!scanResult.allowed)
    {
        return {
            true,
            403,
            false,
            "",
            scanResult.field,
            scanResult.detection
        };
    }

    return {
        true,
        200,
        true,
        "",
        "",
        {}
    };
}
}

SecurityScanResult SecurityService::scanRequest(
    const std::string& authorizationHeader,
    const Json::Value& requestData
)
{
    return runScan(
        authorizationHeader,
        requestData,
        false
    );
}

SecurityScanResult SecurityService::scanSqlInjection(
    const std::string& authorizationHeader,
    const Json::Value& requestData
)
{
    return runScan(
        authorizationHeader,
        requestData,
        true
    );
}