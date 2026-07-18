#pragma once

#include "models/BackendRegistration.h"

#include <optional>
#include <string>
#include <vector>

namespace webhawk::repositories
{
class BackendRepository
{
public:
    static int countBackends();

    static webhawk::models::BackendRegistration createBackend(
        int userId,
        const std::string& serviceName,
        const std::string& targetUrl,
        const std::string& apiKey
    );

    static std::vector<webhawk::models::BackendRegistration>
    findAllByUserId(
        int userId
    );

    static std::optional<webhawk::models::BackendRegistration>
    findByIdAndUserId(
        int backendId,
        int userId
    );

    static std::optional<webhawk::models::BackendRegistration>
    findActiveByApiKey(
        const std::string& apiKey
    );

    static std::optional<webhawk::models::BackendRegistration>
    updateBackend(
        int backendId,
        int userId,
        const std::string& serviceName,
        const std::string& targetUrl,
        bool isActive
    );

    static std::optional<webhawk::models::BackendRegistration>
    disableBackend(
        int backendId,
        int userId
    );
};
}