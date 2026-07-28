#include "controllers/AnalyticsController.h"

#include "services/AnalyticsService.h"

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
        drogon::HttpResponse::
            newHttpJsonResponse(body);

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(
            statusCode
        )
    );

    return response;
}

int integerParameter(
    const drogon::HttpRequestPtr& request,
    const std::string& name,
    int defaultValue
)
{
    const std::string value =
        request->getParameter(name);

    if (value.empty())
    {
        return defaultValue;
    }

    try
    {
        return std::stoi(value);
    }
    catch (...)
    {
        return -1;
    }
}

void sendAnalytics(
    const webhawk::services::
        AnalyticsResult& result,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>& callback
)
{
    if (!result.success)
    {
        callback(errorResponse(
            result.message,
            result.statusCode
        ));

        return;
    }

    callback(
        drogon::HttpResponse::
            newHttpJsonResponse(
                result.data
            )
    );
}
}

void AnalyticsController::summary(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    try
    {
        sendAnalytics(
            webhawk::services::
                AnalyticsService::getSummary(
                    request->getHeader(
                        "Authorization"
                    )
                ),
            callback
        );
    }
    catch (...)
    {
        callback(errorResponse(
            "Could not load analytics summary",
            500
        ));
    }
}

void AnalyticsController::attacksByType(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    try
    {
        sendAnalytics(
            webhawk::services::
                AnalyticsService::
                    getAttacksByType(
                        request->getHeader(
                            "Authorization"
                        )
                    ),
            callback
        );
    }
    catch (...)
    {
        callback(errorResponse(
            "Could not load attack statistics",
            500
        ));
    }
}

void AnalyticsController::recentAttacks(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    try
    {
        const int limit =
            integerParameter(
                request,
                "limit",
                10
            );

        sendAnalytics(
            webhawk::services::
                AnalyticsService::
                    getRecentAttacks(
                        request->getHeader(
                            "Authorization"
                        ),
                        limit
                    ),
            callback
        );
    }
    catch (...)
    {
        callback(errorResponse(
            "Could not load recent attacks",
            500
        ));
    }
}

void AnalyticsController::attacksOverTime(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    try
    {
        const int days =
            integerParameter(
                request,
                "days",
                7
            );

        sendAnalytics(
            webhawk::services::
                AnalyticsService::
                    getAttacksOverTime(
                        request->getHeader(
                            "Authorization"
                        ),
                        days
                    ),
            callback
        );
    }
    catch (...)
    {
        callback(errorResponse(
            "Could not load attack timeline",
            500
        ));
    }
}