#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class SecurityLogController
    : public drogon::HttpController<
        SecurityLogController
    >
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(
        SecurityLogController::list,
        "/logs/security",
        drogon::Get
    );

    METHOD_LIST_END

    void list(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );
};
}