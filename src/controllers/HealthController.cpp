#include "controllers/HealthController.h"

using namespace webhawk::controllers;

void HealthController::health(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    Json::Value responseBody;

    responseBody["service"] = "WebHawk Lite C++";
    responseBody["status"] = "ok";
    responseBody["version"] = "0.1.0";

    auto response = drogon::HttpResponse::newHttpJsonResponse(responseBody);

    callback(response);
}