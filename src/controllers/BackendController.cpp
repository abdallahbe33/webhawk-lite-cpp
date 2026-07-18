#include "controllers/BackendController.h"

#include "services/BackendService.h"

#include <optional>

using namespace webhawk::controllers;

namespace
{
drogon::HttpResponsePtr errorResponse(
    const std::string& message,
    int statusCode
)
{
    Json::Value body;
    body["error"] = message;

    auto response =
        drogon::HttpResponse::newHttpJsonResponse(body);

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(statusCode)
    );

    return response;
}

drogon::HttpResponsePtr backendResponse(
    const std::string& message,
    const webhawk::models::BackendRegistration& backend,
    int statusCode
)
{
    Json::Value body;
    body["message"] = message;
    body["backend"] = backend.toJson();

    auto response =
        drogon::HttpResponse::newHttpJsonResponse(body);

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(statusCode)
    );

    return response;
}
}

void BackendController::registerBackend(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    const auto json = request->getJsonObject();

    if (json == nullptr)
    {
        callback(errorResponse("JSON body is required", 400));
        return;
    }

    try
    {
        const auto result =
            webhawk::services::BackendService::registerBackend(
                request->getHeader("Authorization"),
                json->get("service_name", "").asString(),
                json->get("target_url", "").asString()
            );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));
            return;
        }

        callback(backendResponse(
            result.message,
            result.backend,
            result.statusCode
        ));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not register backend",
            500
        ));
    }
}

void BackendController::listBackends(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    try
    {
        const auto result =
            webhawk::services::BackendService::getBackends(
                request->getHeader("Authorization")
            );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));
            return;
        }

        Json::Value backends(Json::arrayValue);

        for (const auto& backend : result.backends)
        {
            backends.append(backend.toJson());
        }

        Json::Value body;

        body["count"] = static_cast<Json::UInt64>(
            result.backends.size()
        );

        body["backends"] = backends;

        callback(
            drogon::HttpResponse::newHttpJsonResponse(body)
        );
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not load backends",
            500
        ));
    }
}

void BackendController::getBackend(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    int backendId
)
{
    try
    {
        const auto result =
            webhawk::services::BackendService::getBackend(
                request->getHeader("Authorization"),
                backendId
            );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));
            return;
        }

        callback(backendResponse(
            result.message,
            result.backend,
            result.statusCode
        ));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not load backend",
            500
        ));
    }
}

void BackendController::updateBackend(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    int backendId
)
{
    const auto json = request->getJsonObject();

    if (json == nullptr)
    {
        callback(errorResponse("JSON body is required", 400));
        return;
    }

    std::optional<std::string> serviceName;
    std::optional<std::string> targetUrl;
    std::optional<bool> isActive;

    if (json->isMember("service_name"))
    {
        if (!(*json)["service_name"].isString())
        {
            callback(errorResponse(
                "service_name must be a string",
                400
            ));
            return;
        }

        serviceName =
            (*json)["service_name"].asString();
    }

    if (json->isMember("target_url"))
    {
        if (!(*json)["target_url"].isString())
        {
            callback(errorResponse(
                "target_url must be a string",
                400
            ));
            return;
        }

        targetUrl =
            (*json)["target_url"].asString();
    }

    if (json->isMember("is_active"))
    {
        if (!(*json)["is_active"].isBool())
        {
            callback(errorResponse(
                "is_active must be a boolean",
                400
            ));
            return;
        }

        isActive =
            (*json)["is_active"].asBool();
    }

    try
    {
        const auto result =
            webhawk::services::BackendService::updateBackend(
                request->getHeader("Authorization"),
                backendId,
                serviceName,
                targetUrl,
                isActive
            );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));
            return;
        }

        callback(backendResponse(
            result.message,
            result.backend,
            result.statusCode
        ));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not update backend",
            500
        ));
    }
}

void BackendController::disableBackend(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    int backendId
)
{
    try
    {
        const auto result =
            webhawk::services::BackendService::disableBackend(
                request->getHeader("Authorization"),
                backendId
            );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));
            return;
        }

        callback(backendResponse(
            result.message,
            result.backend,
            result.statusCode
        ));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not disable backend",
            500
        ));
    }
}