#pragma once

#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>

#include <functional>
#include <string>

namespace webhawk::services
{
class ProxyService
{
public:
    static void forward(
        const drogon::HttpRequestPtr& request,
        std::function<void(
            const drogon::HttpResponsePtr&
        )>&& callback,
        const std::string& apiKey,
        const std::string& targetPath
    );
};
}