#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class AnalyticsController
    : public drogon::HttpController<
        AnalyticsController
    >
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(
        AnalyticsController::summary,
        "/analytics/summary",
        drogon::Get
    );

    ADD_METHOD_TO(
        AnalyticsController::attacksByType,
        "/analytics/attacks-by-type",
        drogon::Get
    );

    ADD_METHOD_TO(
        AnalyticsController::recentAttacks,
        "/analytics/recent-attacks",
        drogon::Get
    );

    ADD_METHOD_TO(
        AnalyticsController::attacksOverTime,
        "/analytics/attacks-over-time",
        drogon::Get
    );

    METHOD_LIST_END

    void summary(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );

    void attacksByType(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );

    void recentAttacks(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );

    void attacksOverTime(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );
};
}
