#include "controllers/RateLimitController.h"

#include "repositories/BackendRepository.h"
#include "security/AuthMiddleware.h"
#include "security/RateLimiter.h"
#include "repositories/SecurityLogRepository.h"
#include <stdexcept>

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
        drogon::HttpResponse::newHttpJsonResponse(
            body
        );

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(
            statusCode
        )
    );

    return response;
}

std::string clientIp(
    const drogon::HttpRequestPtr& request
)
{
    std::string ipAddress =
        request->peerAddr().toIp();

    return ipAddress.empty()
        ? "127.0.0.1"
        : ipAddress;
}
}

void RateLimitController::check(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    const auto authentication =
        webhawk::security::AuthMiddleware::
            authenticate(
                request->getHeader(
                    "Authorization"
                )
            );

    if (!authentication.success)
    {
        callback(errorResponse(
            authentication.message,
            authentication.statusCode
        ));

        return;
    }

    const auto json =
        request->getJsonObject();

    if (json == nullptr)
    {
        callback(errorResponse(
            "JSON body is required",
            400
        ));

        return;
    }

    const int backendId =
        json->get("backend_id", 0).asInt();

    const std::string endpoint =
        json->get("endpoint", "").asString();

    const std::string ipAddress =
        json->get(
            "ip_address",
            clientIp(request)
        ).asString();

    if (
        backendId <= 0
        || endpoint.empty()
    )
    {
        callback(errorResponse(
            "backend_id and endpoint are required",
            400
        ));

        return;
    }

    try
    {
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
            callback(errorResponse(
                "Active backend was not found",
                404
            ));

            return;
        }

        const auto result =
            webhawk::security::RateLimiter::check(
                backendId,
                ipAddress,
                endpoint
            );
        webhawk::repositories::
         SecurityLogRepository::createLog(
             backendId,
            ipAddress,
            "POST",
            endpoint,
            result.allowed
                  ? "NONE"
                : "RATE_LIMIT",
            !result.allowed,
            *json
            );
        auto response =
            drogon::HttpResponse::
                newHttpJsonResponse(
                    result.toJson()
                );

        response->setStatusCode(
            static_cast<drogon::HttpStatusCode>(
                result.statusCode
            )
        );

        response->addHeader(
            "X-RateLimit-Limit",
            std::to_string(
                result.requestLimit
            )
        );

        response->addHeader(
            "X-RateLimit-Remaining",
            std::to_string(
                result.state.remainingRequests
            )
        );

        if (!result.allowed)
        {
            response->addHeader(
                "Retry-After",
                std::to_string(
                    result.state.retryAfterSeconds
                )
            );
        }

        callback(response);
    }
    catch (const std::invalid_argument& exception)
    {
        callback(errorResponse(
            exception.what(),
            400
        ));
    }
    catch (const std::exception&)
    {
        callback(errorResponse(
            "Rate limit check failed due to an internal error",
            500
        ));
    }
}