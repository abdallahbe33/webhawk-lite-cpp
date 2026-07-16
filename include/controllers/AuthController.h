#pragma once

#include <drogon/HttpController.h>

namespace webhawk::controllers
{
class AuthController : public drogon::HttpController<AuthController>
{
public:
    METHOD_LIST_BEGIN
    ADD_METHOD_TO(AuthController::registerUser, "/auth/register", drogon::Post);
    METHOD_LIST_END

    void registerUser(
        const drogon::HttpRequestPtr& request,
        std::function<void(const drogon::HttpResponsePtr&)>&& callback
    );
};
}