#include "controllers/AuthController.h"

#include "services/AuthService.h"

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

    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(statusCode)
    );

    return response;
}

std::string clientIp(
    const drogon::HttpRequestPtr& request
)
{
    const std::string forwardedFor = request->getHeader(
        "X-Forwarded-For"
    );

    if (!forwardedFor.empty())
    {
        const std::size_t comma = forwardedFor.find(',');
        return forwardedFor.substr(0, comma);
    }

    return request->peerAddr().toIp();
}
}

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

void AuthController::loginUser(
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
        const auto result = webhawk::services::AuthService::login(
            json->get("email", "").asString(),
            json->get("password", "").asString(),
            clientIp(request)
        );

        if (!result.success)
        {
            callback(errorResponse(result.message, result.statusCode));
            return;
        }

        Json::Value body;
        body["message"] = result.message;
        body["access_token"] = result.accessToken;
        body["token_type"] = result.tokenType;
        body["expires_at"] = result.expiresAt;
        body["user"] = result.user.toJson();

        callback(drogon::HttpResponse::newHttpJsonResponse(body));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Login failed due to an internal error",
            500
        ));
    }
}

void AuthController::listSessions(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    try
    {
        const auto result =
            webhawk::services::AuthService::getActiveSessions(
                request->getHeader("Authorization")
            );

        if (!result.success)
        {
            callback(errorResponse(result.message, result.statusCode));
            return;
        }

        Json::Value sessions(Json::arrayValue);

        for (const auto& session : result.sessions)
        {
            sessions.append(session.toJson());
        }

        Json::Value body;
        body["count"] = static_cast<Json::UInt64>(
            result.sessions.size()
        );
        body["sessions"] = sessions;

        callback(drogon::HttpResponse::newHttpJsonResponse(body));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse(
            "Could not load active sessions",
            500
        ));
    }
}

void AuthController::logoutUser(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    try
    {
        const auto result = webhawk::services::AuthService::logout(
            request->getHeader("Authorization")
        );

        if (!result.success)
        {
            callback(errorResponse(result.message, result.statusCode));
            return;
        }

        Json::Value body;
        body["message"] = result.message;

        callback(drogon::HttpResponse::newHttpJsonResponse(body));
    }
    catch (const std::exception& exception)
    {
        callback(errorResponse("Logout failed", 500));
    }
}
