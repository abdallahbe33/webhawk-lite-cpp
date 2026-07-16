#include "controllers/AuthController.h"

#include "services/AuthService.h"

using namespace webhawk::controllers;

void AuthController::registerUser(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    const auto json = request->getJsonObject();

    if (json == nullptr)
    {
        Json::Value body;

        body["error"] = "JSON body is required";

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(drogon::k400BadRequest);

        callback(response);
        return;
    }

    const std::string name =
        json->get("name", "").asString();

    const std::string email =
        json->get("email", "").asString();

    const std::string password =
        json->get("password", "").asString();

    const auto result =
        webhawk::services::AuthService::registerUser(
            name,
            email,
            password
        );

    Json::Value body;

    if (!result.success)
    {
        body["error"] = result.message;

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(
            static_cast<drogon::HttpStatusCode>(
                result.statusCode
            )
        );

        callback(response);
        return;
    }

    body["message"] = result.message;
    body["user"] = result.user.toJson();

    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(drogon::k201Created);

    callback(response);
}