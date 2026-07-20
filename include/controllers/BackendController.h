#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class BackendController
    : public drogon::HttpController<BackendController>
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(
        BackendController::registerBackend,
        "/backends",
        drogon::Post
    );

    ADD_METHOD_TO(
        BackendController::listBackends,
        "/backends",
        drogon::Get
    );

    ADD_METHOD_TO(
        BackendController::getBackend,
        "/backends/{1}",
        drogon::Get
    );

    ADD_METHOD_TO(
        BackendController::updateBackend,
        "/backends/{1}",
        drogon::Put
    );

    ADD_METHOD_TO(
        BackendController::disableBackend,
        "/backends/{1}",
        drogon::Delete
    );

    METHOD_LIST_END

    void registerBackend(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    void listBackends(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    void getBackend(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        int backendId
    );

    void updateBackend(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        int backendId
    );

    void disableBackend(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback,
        int backendId
    );
};
}