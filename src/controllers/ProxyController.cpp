#include "controllers/ProxyController.h"

#include "proxy/ProxyUtils.h"
#include "services/ProxyService.h"

using namespace webhawk::controllers;

void ProxyController::proxy(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    const auto parsed =
        webhawk::proxy::ProxyUtils::
            parseProxyPath(
                request->getPath()
            );

    if (!parsed.has_value())
    {
        Json::Value body;
        body["error"] =
            "Invalid proxy URL";

        auto response =
            drogon::HttpResponse::
                newHttpJsonResponse(body);

        response->setStatusCode(
            drogon::k400BadRequest
        );

        callback(response);
        return;
    }

    webhawk::services::
        ProxyService::forward(
            request,
            std::move(callback),
            parsed->apiKey,
            parsed->targetPath
        );
}