#include "services/BackendService.h"

#include "repositories/BackendRepository.h"
#include "security/ApiKeyGenerator.h"
#include "security/AuthMiddleware.h"

#include <regex>

using namespace webhawk::services;

std::string BackendService::trim(
    const std::string& value
)
{
    const auto first = value.find_first_not_of(" \t\n\r");

    if (first == std::string::npos)
    {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\n\r");

    return value.substr(
        first,
        last - first + 1
    );
}

bool BackendService::isValidServiceName(
    const std::string& serviceName
)
{
    return !serviceName.empty()
        && serviceName.size() <= 150;
}

bool BackendService::isValidTargetUrl(
    const std::string& targetUrl
)
{
    if (targetUrl.empty() || targetUrl.size() > 2048)
    {
        return false;
    }

    static const std::regex urlPattern(
        R"(^https?://[^\s/]+(?:/[^\s]*)?$)",
        std::regex::icase
    );

    return std::regex_match(
        targetUrl,
        urlPattern
    );
}

BackendResult BackendService::registerBackend(
    const std::string& authorizationHeader,
    const std::string& serviceName,
    const std::string& targetUrl
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
            authentication.message,
            {}
        };
    }

    const std::string cleanServiceName = trim(serviceName);
    const std::string cleanTargetUrl = trim(targetUrl);

    if (!isValidServiceName(cleanServiceName))
    {
        return {
            false,
            400,
            "Service name is required and must not exceed 150 characters",
            {}
        };
    }

    if (!isValidTargetUrl(cleanTargetUrl))
    {
        return {
            false,
            400,
            "Target URL must be a valid HTTP or HTTPS URL",
            {}
        };
    }

    const std::string apiKey =
        webhawk::security::ApiKeyGenerator::generate();

    const auto backend =
        webhawk::repositories::BackendRepository::createBackend(
            authentication.context.userId,
            cleanServiceName,
            cleanTargetUrl,
            apiKey
        );

    return {
        true,
        201,
        "Backend registered successfully",
        backend
    };
}

BackendListResult BackendService::getBackends(
    const std::string& authorizationHeader
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
            authentication.message,
            {}
        };
    }

    const auto backends =
        webhawk::repositories::BackendRepository::findAllByUserId(
            authentication.context.userId
        );

    return {
        true,
        200,
        "Backends returned successfully",
        backends
    };
}

BackendResult BackendService::getBackend(
    const std::string& authorizationHeader,
    int backendId
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
            authentication.message,
            {}
        };
    }

    if (backendId <= 0)
    {
        return {
            false,
            400,
            "Backend ID must be a positive number",
            {}
        };
    }

    const auto backend =
        webhawk::repositories::BackendRepository::findByIdAndUserId(
            backendId,
            authentication.context.userId
        );

    if (!backend.has_value())
    {
        return {
            false,
            404,
            "Backend not found",
            {}
        };
    }

    return {
        true,
        200,
        "Backend returned successfully",
        backend.value()
    };
}

BackendResult BackendService::updateBackend(
    const std::string& authorizationHeader,
    int backendId,
    const std::optional<std::string>& serviceName,
    const std::optional<std::string>& targetUrl,
    const std::optional<bool>& isActive
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
            authentication.message,
            {}
        };
    }

    if (
        !serviceName.has_value()
        && !targetUrl.has_value()
        && !isActive.has_value()
    )
    {
        return {
            false,
            400,
            "At least one update field is required",
            {}
        };
    }

    const auto existingBackend =
        webhawk::repositories::BackendRepository::findByIdAndUserId(
            backendId,
            authentication.context.userId
        );

    if (!existingBackend.has_value())
    {
        return {
            false,
            404,
            "Backend not found",
            {}
        };
    }

    const std::string cleanServiceName = serviceName.has_value()
        ? trim(serviceName.value())
        : existingBackend->serviceName;

    const std::string cleanTargetUrl = targetUrl.has_value()
        ? trim(targetUrl.value())
        : existingBackend->targetUrl;

    const bool updatedActiveStatus = isActive.value_or(
        existingBackend->isActive
    );

    if (!isValidServiceName(cleanServiceName))
    {
        return {
            false,
            400,
            "Service name is required and must not exceed 150 characters",
            {}
        };
    }

    if (!isValidTargetUrl(cleanTargetUrl))
    {
        return {
            false,
            400,
            "Target URL must be a valid HTTP or HTTPS URL",
            {}
        };
    }

    const auto updatedBackend =
        webhawk::repositories::BackendRepository::updateBackend(
            backendId,
            authentication.context.userId,
            cleanServiceName,
            cleanTargetUrl,
            updatedActiveStatus
        );

    if (!updatedBackend.has_value())
    {
        return {
            false,
            404,
            "Backend not found",
            {}
        };
    }

    return {
        true,
        200,
        "Backend updated successfully",
        updatedBackend.value()
    };
}

BackendResult BackendService::disableBackend(
    const std::string& authorizationHeader,
    int backendId
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
            authentication.message,
            {}
        };
    }

    const auto backend =
        webhawk::repositories::BackendRepository::disableBackend(
            backendId,
            authentication.context.userId
        );

    if (!backend.has_value())
    {
        return {
            false,
            404,
            "Backend not found",
            {}
        };
    }

    return {
        true,
        200,
        "Backend disabled successfully",
        backend.value()
    };
}