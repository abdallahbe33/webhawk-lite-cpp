#pragma once

#include "models/BackendRegistration.h"

#include <optional>
#include <string>
#include <vector>

namespace webhawk::services
{
struct BackendResult
{
    bool success{};
    int statusCode{};
    std::string message;
    webhawk::models::BackendRegistration backend;
};

struct BackendListResult
{
    bool success{};
    int statusCode{};
    std::string message;
    std::vector<webhawk::models::BackendRegistration> backends;
};

class BackendService
{
public:
    static BackendResult registerBackend(
        const std::string& authorizationHeader,
        const std::string& serviceName,
        const std::string& targetUrl
    );

    static BackendListResult getBackends(
        const std::string& authorizationHeader
    );

    static BackendResult getBackend(
        const std::string& authorizationHeader,
        int backendId
    );

    static BackendResult updateBackend(
        const std::string& authorizationHeader,
        int backendId,
        const std::optional<std::string>& serviceName,
        const std::optional<std::string>& targetUrl,
        const std::optional<bool>& isActive
    );

    static BackendResult disableBackend(
        const std::string& authorizationHeader,
        int backendId
    );

private:
    static std::string trim(
        const std::string& value
    );

    static bool isValidServiceName(
        const std::string& serviceName
    );

    static bool isValidTargetUrl(
        const std::string& targetUrl
    );
};
}