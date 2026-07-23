#include "security/RequestScanner.h"

#include "security/SqlInjectionDetector.h"
#include "security/XssDetector.h"

using namespace webhawk::security;

DetectionResult RequestScanner::scanText(
    const std::string& value,
    ScanMode mode
)
{
    const auto sqlDetection =
        SqlInjectionDetector::scan(value);

    if (
        sqlDetection.detected
        || mode == ScanMode::SqlInjectionOnly
    )
    {
        return sqlDetection;
    }

    return XssDetector::scan(value);
}

std::optional<RequestScanner::LocatedDetection>
RequestScanner::scanNode(
    const Json::Value& value,
    const std::string& fieldPath,
    ScanMode mode
)
{
    if (value.isString())
    {
        const auto detection = scanText(
            value.asString(),
            mode
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
            const std::string childPath =
                fieldPath.empty()
                    ? name
                    : fieldPath + "." + name;

            // Parameter names can also contain attacks.
            const auto keyDetection = scanText(
                name,
                mode
            );

            if (keyDetection.detected)
            {
                return LocatedDetection{
                    childPath + ".$key",
                    keyDetection
                };
            }

            const auto child = scanNode(
                value[name],
                childPath,
                mode
            );

            if (child.has_value())
            {
                return child;
            }
        }
    }
    else if (value.isArray())
    {
        for (
            Json::ArrayIndex index = 0;
            index < value.size();
            ++index
        )
        {
            const auto child = scanNode(
                value[index],
                fieldPath
                    + "["
                    + std::to_string(index)
                    + "]",
                mode
            );

            if (child.has_value())
            {
                return child;
            }
        }
    }

    return std::nullopt;
}

RequestScanResult RequestScanner::scan(
    const Json::Value& requestData
)
{
    const auto result = scanNode(
        requestData,
        "",
        ScanMode::All
    );

    return result.has_value()
        ? RequestScanResult{
            false,
            result->field,
            result->detection
        }
        : RequestScanResult{};
}

RequestScanResult RequestScanner::scanSqlInjection(
    const Json::Value& requestData
)
{
    const auto result = scanNode(
        requestData,
        "",
        ScanMode::SqlInjectionOnly
    );

    return result.has_value()
        ? RequestScanResult{
            false,
            result->field,
            result->detection
        }
        : RequestScanResult{};
}