#include "services/SecurityService.h"

#include "security/AuthMiddleware.h"
#include "security/SqlInjectionDetector.h"

using namespace webhawk::services;

std::optional<SecurityService::LocatedDetection>
SecurityService::scanNode(
    const Json::Value& value,
    const std::string& fieldPath
)
{
    if (value.isString())
    {
        const auto detection =
            webhawk::security::SqlInjectionDetector::scan(
                value.asString()
            );

        if (detection.detected)
        {
            return LocatedDetection{
                fieldPath,
                detection
            };
        }

        return std::nullopt;
    }

    if (value.isObject())
    {
        for (const auto& name : value.getMemberNames())
        {
            const std::string childPath = fieldPath.empty()
                ? name
                : fieldPath + "." + name;

            // Scan parameter names as well as their values.
            const auto nameDetection =
                webhawk::security::SqlInjectionDetector::scan(
                    name
                );

            if (nameDetection.detected)
            {
                return LocatedDetection{
                    childPath + ".$key",
                    nameDetection
                };
            }

            const auto childDetection = scanNode(
                value[name],
                childPath
            );

            if (childDetection.has_value())
            {
                return childDetection;
            }
        }

        return std::nullopt;
    }

    if (value.isArray())
    {
        for (
            Json::ArrayIndex index = 0;
            index < value.size();
            ++index
        )
        {
            const std::string childPath = fieldPath
                + "["
                + std::to_string(index)
                + "]";

            const auto childDetection = scanNode(
                value[index],
                childPath
            );

            if (childDetection.has_value())
            {
                return childDetection;
            }
        }
    }

    return std::nullopt;
}

SecurityScanResult SecurityService::scanSqlInjection(
    const std::string& authorizationHeader,
    const Json::Value& requestData
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

    if (!requestData.isObject() || requestData.empty())
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

    const auto locatedDetection = scanNode(
        requestData,
        ""
    );

    if (locatedDetection.has_value())
    {
        return {
            true,
            403,
            false,
            "",
            locatedDetection->field,
            locatedDetection->detection
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