#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class AuthController : public drogon::HttpController<AuthController>
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::registerUser, "/auth/register", drogon::Post);
    ADD_METHOD_TO(AuthController::loginUser, "/auth/login", drogon::Post);
    ADD_METHOD_TO(AuthController::logoutUser, "/auth/logout", drogon::Post);
    ADD_METHOD_TO(AuthController::listSessions, "/auth/sessions", drogon::Get);
    METHOD_LIST_END

    void registerUser(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    void loginUser(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    void logoutUser(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );

    void listSessions(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
}
