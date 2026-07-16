#include "controllers/DatabaseHealthController.h"

#include "repositories/BackendRepository.h"
#include "repositories/RateLimitRepository.h"
#include "repositories/SecurityLogRepository.h"
#include "repositories/SessionRepository.h"
#include "repositories/UserRepository.h"

using namespace webhawk::controllers;

void DatabaseHealthController::health(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback
)
{
    Json::Value body;

    try
    {
        body["status"] = "ok";
        body["database"] = "connected";
        body["tables"]["users"] =
            webhawk::repositories::UserRepository::countUsers();
        body["tables"]["user_sessions"] =
            webhawk::repositories::SessionRepository::countSessions();
        body["tables"]["backend_registration"] =
            webhawk::repositories::BackendRepository::countBackends();
        body["tables"]["security_logs"] =
            webhawk::repositories::SecurityLogRepository::countSecurityLogs();
        body["tables"]["rate_limit"] =
            webhawk::repositories::RateLimitRepository::countRateLimitRecords();

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        callback(response);
    }
    catch (const std::exception& error)
    {
        body["status"] = "error";
        body["database"] = "not_connected";
        body["message"] = error.what();

        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->setStatusCode(drogon::k500InternalServerError);

        callback(response);
    }
}