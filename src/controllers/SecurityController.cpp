#include "controllers/SecurityController.h"

#include "services/SecurityService.h"

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
        static_cast<drogon::HttpStatusCode>(
            statusCode
        )
    );

    return response;
}

void sendScanResponse(
    const webhawk::services::SecurityScanResult& result,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>& callback
)
{
    if (!result.success)
    {
        callback(errorResponse(
            result.error,
            result.statusCode
        ));

        return;
    }

    Json::Value body = result.detection.toJson();

    body["allowed"] = result.allowed;
    body["field"] = result.field;

    if (result.allowed)
    {
        body["message"] = "Request data is safe";
    }

    auto response =
        drogon::HttpResponse::newHttpJsonResponse(
            body
        );

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(
            result.statusCode
        )
    );

    callback(response);
}
}

void SecurityController::scanRequest(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    const auto json = request->getJsonObject();

    if (json == nullptr)
    {
        callback(errorResponse(
            "JSON body is required",
            400
        ));

        return;
    }

    try
    {
        const auto result =
            webhawk::services::SecurityService::
                scanRequest(
                    request->getHeader(
                        "Authorization"
                    ),
                    *json
                );

        sendScanResponse(result, callback);
    }
    catch (const std::exception&)
    {
        callback(errorResponse(
            "Security scan failed due to an internal error",
            500
        ));
    }
}

void SecurityController::scanSqlInjection(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    const auto json = request->getJsonObject();

    if (json == nullptr)
    {
        callback(errorResponse(
            "JSON body is required",
            400
        ));

        return;
    }

    try
    {
        const auto result =
            webhawk::services::SecurityService::
                scanSqlInjection(
                    request->getHeader(
                        "Authorization"
                    ),
                    *json
                );

        sendScanResponse(result, callback);
    }
    catch (const std::exception&)
    {
        callback(errorResponse(
            "Security scan failed due to an internal error",
            500
        ));
    }
}