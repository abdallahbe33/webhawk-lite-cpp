#include "controllers/SecurityLogController.h"

#include "services/SecurityLogService.h"

#include <algorithm>
#include <cctype>
#include <optional>

using namespace webhawk::controllers;

namespace
{
drogon::HttpResponsePtr errorResponse(
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

std::optional<int> positiveInt(
    const std::string& value,
    int defaultValue
)
{
    if (value.empty())
    {
        return defaultValue;
    }

    try
    {
        const int parsed =
            std::stoi(value);

        if (parsed < 1)
        {
            return std::nullopt;
        }

        return parsed;
    }
    catch (...)
    {
        return std::nullopt;
    }
}
}

void SecurityLogController::list(
    const drogon::HttpRequestPtr& request,
    std::function<void(
        const drogon::HttpResponsePtr&
    )>&& callback
)
{
    const auto page = positiveInt(
        request->getParameter("page"),
        1
    );

    const auto pageSize = positiveInt(
        request->getParameter("page_size"),
        20
    );

    if (
        !page.has_value()
        || !pageSize.has_value()
        || *pageSize > 100
    )
    {
        callback(errorResponse(
            "Invalid page or page_size",
            400
        ));

        return;
    }

    webhawk::repositories::
        SecurityLogQuery query;

    query.page = *page;
    query.pageSize = *pageSize;

    query.attackType =
        request->getParameter(
            "attack_type"
        );

    std::transform(
        query.attackType.begin(),
        query.attackType.end(),
        query.attackType.begin(),
        [](unsigned char character)
        {
            return static_cast<char>(
                std::toupper(character)
            );
        }
    );

    const std::string blocked =
        request->getParameter("blocked");

    if (
        blocked == "true"
        || blocked == "1"
    )
    {
        query.blockedFilter = 1;
    }
    else if (
        blocked == "false"
        || blocked == "0"
    )
    {
        query.blockedFilter = 0;
    }
    else if (!blocked.empty())
    {
        callback(errorResponse(
            "blocked must be true or false",
            400
        ));

        return;
    }

    const std::string backendId =
        request->getParameter(
            "backend_id"
        );

    if (!backendId.empty())
    {
        const auto parsed =
            positiveInt(backendId, 0);

        if (!parsed.has_value())
        {
            callback(errorResponse(
                "backend_id must be positive",
                400
            ));

            return;
        }

        query.backendId = *parsed;
    }

    try
    {
        const auto result =
            webhawk::services::
                SecurityLogService::getLogs(
                    request->getHeader(
                        "Authorization"
                    ),
                    query
                );

        if (!result.success)
        {
            callback(errorResponse(
                result.message,
                result.statusCode
            ));

            return;
        }

        Json::Value logs(
            Json::arrayValue
        );

        for (const auto& log : result.logs)
        {
            logs.append(log.toJson());
        }

        Json::Value body;

        body["count"] =
            Json::UInt64(
                result.logs.size()
            );

        body["total"] =
            Json::Int64(result.total);

        body["page"] = result.page;
        body["page_size"] =
            result.pageSize;

        body["total_pages"] =
            result.total == 0
                ? 0
                : static_cast<int>(
                    (
                        result.total
                        + result.pageSize
                        - 1
                    ) / result.pageSize
                );

        body["logs"] = logs;

        callback(
            drogon::HttpResponse::
                newHttpJsonResponse(body)
        );
    }
    catch (const std::exception&)
    {
        callback(errorResponse(
            "Could not load security logs",
            500
        ));
    }
}