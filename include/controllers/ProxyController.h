#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class ProxyController
    : public drogon::HttpController<
        ProxyController
    >
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_VIA_REGEX(
        ProxyController::proxy,
        R"(^/proxy/[^/]+(?:/.*)?$)",
        drogon::Get,
        drogon::Post,
        drogon::Put,
        drogon::Delete,
        drogon::Patch,
        drogon::Options,
        drogon::Head
    );

    METHOD_LIST_END

    void proxy(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback
    );
};
}