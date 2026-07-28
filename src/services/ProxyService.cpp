#include "services/ProxyService.h"

#include "config/AppConfig.h"
#include "proxy/ProxyUtils.h"
#include "repositories/BackendRepository.h"
#include "repositories/SecurityLogRepository.h"
#include "security/RateLimiter.h"
#include "security/RequestScanner.h"

#include <drogon/HttpClient.h>
#include <drogon/HttpTypes.h>

using namespace webhawk::services;

namespace
{
drogon::HttpResponsePtr jsonError(
    const std::string& message,
    int statusCode
)
{
    Json::Value body;
    body["error"] = message;

    auto response =
        drogon::HttpResponse::
            newHttpJsonResponse(body);

    response->setStatusCode(
        static_cast<drogon::HttpStatusCode>(
            statusCode
        )
    );

    return response;
}

std::string clientIp(
    const drogon::HttpRequestPtr& request
)
{
    const std::string ip =
        request->peerAddr().toIp();

    if (ip.empty())
    {
        return "unknown";
    }

    return ip.size() > 45
        ? ip.substr(0, 45)
        : ip;
}

Json::Value buildScanData(
    const drogon::HttpRequestPtr& request,
    int backendId,
    const std::string& targetPath
)
{
    Json::Value data;

    data["backend_id"] = backendId;
    data["method"] =
        request->methodString();

    data["path"] = targetPath;
    data["query"] =
        request->getQuery();

    const auto jsonBody =
        request->getJsonObject();

    if (jsonBody == nullptr)
    {
        data["body"] =
            std::string(
                request->getBody()
            );
    }
    else
    {
        data["body"] = *jsonBody;
    }

    Json::Value headers;

    for (
        const auto& [name, value]
        : request->headers()
    )
    {
        headers[name] =
            webhawk::proxy::ProxyUtils::
                isSensitiveHeader(name)
                    ? "[REDACTED]"
                    : value;
    }

    data["headers"] = headers;

    return data;
}

void writeSecurityLog(
    int backendId,
    const drogon::HttpRequestPtr& request,
    const std::string& targetPath,
    const std::string& attackType,
    bool blocked,
    const Json::Value& scanData
)
{
    webhawk::repositories::
        SecurityLogRepository::createLog(
            backendId,
            clientIp(request),
            request->methodString(),
            targetPath,
            attackType,
            blocked,
            scanData
        );
}
}

void ProxyService::forward(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback,
    const std::string& apiKey,
    const std::string& targetPath
)
{
    try
    {
        const auto backend =
            webhawk::repositories::
                BackendRepository::
                    findActiveByApiKey(
                        apiKey
                    );

        if (!backend.has_value())
        {
            callback(jsonError(
                "Invalid or inactive API key",
                404
            ));

            return;
        }

        const auto bodySize =
            request->getBody().size();

        const auto maximumBodySize =
            static_cast<std::size_t>(
                webhawk::config::AppConfig::
                    proxyMaxBodyBytes()
            );

        if (bodySize > maximumBodySize)
        {
            callback(jsonError(
                "Request body is too large",
                413
            ));

            return;
        }

        const Json::Value scanData =
            buildScanData(
                request,
                backend->id,
                targetPath
            );

        const auto rateLimit =
            webhawk::security::
                RateLimiter::check(
                    backend->id,
                    clientIp(request),
                    targetPath
                );

        if (!rateLimit.allowed)
        {
            writeSecurityLog(
                backend->id,
                request,
                targetPath,
                "RATE_LIMIT",
                true,
                scanData
            );

            auto response =
                drogon::HttpResponse::
                    newHttpJsonResponse(
                        rateLimit.toJson()
                    );

            response->setStatusCode(
                drogon::k429TooManyRequests
            );

            response->addHeader(
                "Retry-After",
                std::to_string(
                    rateLimit.state
                        .retryAfterSeconds
                )
            );

            response->addHeader(
                "X-RateLimit-Limit",
                std::to_string(
                    rateLimit.requestLimit
                )
            );

            response->addHeader(
                "X-RateLimit-Remaining",
                "0"
            );

            callback(response);
            return;
        }

        const auto scanResult =
            webhawk::security::
                RequestScanner::scan(
                    scanData
                );

        if (!scanResult.allowed)
        {
            writeSecurityLog(
                backend->id,
                request,
                targetPath,
                scanResult.detection.attackType,
                true,
                scanData
            );

            Json::Value body =
                scanResult.detection.toJson();

            body["allowed"] = false;
            body["field"] =
                scanResult.field;

            body["message"] =
                "Request blocked by WebHawk";

            auto response =
                drogon::HttpResponse::
                    newHttpJsonResponse(body);

            response->setStatusCode(
                drogon::k403Forbidden
            );

            response->addHeader(
                "X-WebHawk-Status",
                "blocked"
            );

            callback(response);
            return;
        }

        const auto target =
            webhawk::proxy::ProxyUtils::
                parseTargetUrl(
                    backend->targetUrl
                );

        if (!target.has_value())
        {
            callback(jsonError(
                "Registered target URL is invalid",
                500
            ));

            return;
        }

        writeSecurityLog(
            backend->id,
            request,
            targetPath,
            "NONE",
            false,
            scanData
        );

        std::string outgoingPath =
            webhawk::proxy::ProxyUtils::
                joinPaths(
                    target->basePath,
                    targetPath
                );

        if (!request->getQuery().empty())
        {
            outgoingPath +=
                "?"
                + request->getQuery();
        }

        auto outgoing =
            drogon::HttpRequest::
                newHttpRequest();

        outgoing->setMethod(
            request->getMethod()
        );

        outgoing->setPathEncode(false);

        outgoing->setPath(
            outgoingPath
        );

        outgoing->setBody(
            std::string(
                request->getBody()
            )
        );

        for (
            const auto& [name, value]
            : request->headers()
        )
        {
            if (
                !webhawk::proxy::ProxyUtils::
                    isHopByHopHeader(name)
            )
            {
                outgoing->addHeader(
                    name,
                    value
                );
            }
        }

        outgoing->addHeader(
            "X-Forwarded-For",
            clientIp(request)
        );

        outgoing->addHeader(
            "X-Forwarded-Proto",
            request->isOnSecureConnection()
                ? "https"
                : "http"
        );

        outgoing->addHeader(
            "X-WebHawk-Backend-Id",
            std::to_string(
                backend->id
            )
        );

        auto client =
            drogon::HttpClient::
                newHttpClient(
                    target->origin
                );

        const int backendId =
            backend->id;

        client->sendRequest(
            outgoing,

            [
                callback =
                    std::move(callback),
                client,
                backendId
            ](
                drogon::ReqResult result,
                const drogon::HttpResponsePtr&
                    upstream
            ) mutable
            {
                if (
                    result
                        != drogon::ReqResult::Ok
                    || upstream == nullptr
                )
                {
                    const int statusCode =
                        result
                            == drogon::ReqResult::
                                Timeout
                            ? 504
                            : 502;

                    callback(jsonError(
                        statusCode == 504
                            ? "Target backend timed out"
                            : "Target backend is unavailable",
                        statusCode
                    ));

                    return;
                }

                auto response =
                    drogon::HttpResponse::
                        newHttpResponse();

                response->setStatusCode(
                    upstream->getStatusCode()
                );

                response->setBody(
                    std::string(
                        upstream->getBody()
                    )
                );

                for (
                    const auto& [name, value]
                    : upstream->headers()
                )
                {
                    if (
                        !webhawk::proxy::
                            ProxyUtils::
                                isHopByHopHeader(
                                    name
                                )
                    )
                    {
                        response->addHeader(
                            name,
                            value
                        );
                    }
                }

                response->addHeader(
                    "X-WebHawk-Status",
                    "allowed"
                );

                response->addHeader(
                    "X-WebHawk-Backend-Id",
                    std::to_string(
                        backendId
                    )
                );

                callback(response);
            },

            webhawk::config::AppConfig::
                proxyTimeoutSeconds()
        );
    }
    catch (const std::exception&)
    {
        callback(jsonError(
            "Proxy request failed due to "
            "an internal error",
            500
        ));
    }
}