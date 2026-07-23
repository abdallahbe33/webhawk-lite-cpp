#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class RateLimitController
    : public drogon::HttpController<
        RateLimitController
    >
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(
        RateLimitController::check,
        "/security/rate-limit/check",
        drogon::Post
    );

    METHOD_LIST_END

    void check(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );
};
}