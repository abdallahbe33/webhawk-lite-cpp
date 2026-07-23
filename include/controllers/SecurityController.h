#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class SecurityController
    : public drogon::HttpController<SecurityController>
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(
        SecurityController::scanRequest,
        "/security/scan",
        drogon::Post
    );

    ADD_METHOD_TO(
        SecurityController::scanSqlInjection,
        "/security/scan/sql-injection",
        drogon::Post
    );

    METHOD_LIST_END

    void scanRequest(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );

    void scanSqlInjection(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );
};
}