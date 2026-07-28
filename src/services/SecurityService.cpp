#include "services/SecurityService.h"

#include "repositories/BackendRepository.h"
#include "repositories/SecurityLogRepository.h"
#include "security/AuthMiddleware.h"
#include "security/RequestScanner.h"

#include <algorithm>
#include <cctype>

using namespace webhawk::services;

namespace
{
std::string uppercase(
    std::string value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character)
        {
            return static_cast<char>(
                std::toupper(character)
            );
        }
    );

    return value;
}

SecurityScanResult runScan(
    const std::string& authorizationHeader,
    const Json::Value& requestData,
    const std::string& ipAddress,
    bool sqlOnly
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

    const int backendId =
        requestData.get(
            "backend_id",
            0
        ).asInt();

    if (backendId <= 0)
    {
        return {
            false,
            400,
            false,
            "backend_id is required",
            "",
            {}
        };
    }

    const auto backend =
        webhawk::repositories::
            BackendRepository::
                findByIdAndUserId(
                    backendId,
                    authentication.context.userId
                );

    if (
        !backend.has_value()
        || !backend->isActive
    )
    {
        return {
            false,
            404,
            false,
            "Active backend was not found",
            "",
            {}
        };
    }

    const auto scanResult = sqlOnly
        ? webhawk::security::RequestScanner::
            scanSqlInjection(requestData)
        : webhawk::security::RequestScanner::
            scan(requestData);

    std::string method =
        requestData.get(
            "method",
            "POST"
        ).asString();

    method = uppercase(method);

    if (method.empty())
    {
        method = "POST";
    }

    if (method.size() > 20)
    {
        method = method.substr(0, 20);
    }

    std::string endpoint =
        requestData.get(
            "path",
            requestData.get(
                "endpoint",
                "/security/scan"
            )
        ).asString();

    if (endpoint.empty())
    {
        endpoint = "/security/scan";
    }

    if (endpoint.size() > 2048)
    {
        endpoint =
            endpoint.substr(0, 2048);
    }

    std::string safeIpAddress =
        ipAddress.empty()
            ? "unknown"
            : ipAddress;

    if (safeIpAddress.size() > 45)
    {
        safeIpAddress =
            safeIpAddress.substr(0, 45);
    }

    const bool blocked =
        !scanResult.allowed;

    const std::string attackType =
        blocked
            ? scanResult.detection.attackType
            : "NONE";

    webhawk::repositories::
        SecurityLogRepository::createLog(
            backendId,
            safeIpAddress,
            method,
            endpoint,
            attackType,
            blocked,
            requestData
        );

    if (blocked)
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
    const Json::Value& requestData,
    const std::string& ipAddress
)
{
    return runScan(
        authorizationHeader,
        requestData,
        ipAddress,
        false
    );
}

SecurityScanResult
SecurityService::scanSqlInjection(
    const std::string& authorizationHeader,
    const Json::Value& requestData,
    const std::string& ipAddress
)
{
    return runScan(
        authorizationHeader,
        requestData,
        ipAddress,
        true
    );
}