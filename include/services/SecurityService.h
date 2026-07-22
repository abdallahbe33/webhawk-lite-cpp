#pragma once

#include "security/DetectionResult.h"

#include <json/json.h>
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
    static SecurityScanResult scanRequest(
        const std::string& authorizationHeader,
        const Json::Value& requestData
    );

    static SecurityScanResult scanSqlInjection(
        const std::string& authorizationHeader,
        const Json::Value& requestData
    );
};
}