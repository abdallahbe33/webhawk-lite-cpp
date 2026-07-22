#pragma once

#include "security/DetectionResult.h"

#include <json/json.h>
#include <optional>
#include <string>

namespace webhawk::security
{
struct RequestScanResult
{
    bool allowed{true};
    std::string field;
    DetectionResult detection;
};

class RequestScanner
{
public:
    static RequestScanResult scan(
        const Json::Value& requestData
    );

    static RequestScanResult scanSqlInjection(
        const Json::Value& requestData
    );

private:
    enum class ScanMode
    {
        All,
        SqlInjectionOnly
    };

    struct LocatedDetection
    {
        std::string field;
        DetectionResult detection;
    };

    static std::optional<LocatedDetection> scanNode(
        const Json::Value& value,
        const std::string& fieldPath,
        ScanMode mode
    );

    static DetectionResult scanText(
        const std::string& value,
        ScanMode mode
    );
};
}