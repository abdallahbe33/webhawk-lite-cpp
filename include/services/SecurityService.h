#pragma once

#include "security/DetectionResult.h"

#include <json/json.h>
#include <optional>
#include <string>

namespace webhawk::services
{
struct SecurityScanResult
{
    bool success{};
    int statusCode{};
    bool allowed{true};
    std::string error;
    std::string field;
    webhawk::security::DetectionResult detection;
};

class SecurityService
{
public:
    static SecurityScanResult scanSqlInjection(
        const std::string& authorizationHeader,
        const Json::Value& requestData
    );

private:
    struct LocatedDetection
    {
        std::string field;
        webhawk::security::DetectionResult detection;
    };

    static std::optional<LocatedDetection> scanNode(
        const Json::Value& value,
        const std::string& fieldPath
    );
};
}
