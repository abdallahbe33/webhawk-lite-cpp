#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class DatabaseHealthController : public drogon::HttpController<DatabaseHealthController>
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(DatabaseHealthController::health, "/db/health", drogon::Get);
    METHOD_LIST_END

    void health(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
}