#include <drogon/drogon.h>

#include <cstdlib>
#include <functional>
#include <string>

using namespace drogon;

namespace
{
HttpResponsePtr jsonResponse(
    const Json::Value& body,
    HttpStatusCode status = k200OK
)
{
    auto response =
        HttpResponse::newHttpJsonResponse(body);

    response->setStatusCode(status);
    return response;
}

int serverPort()
{
    const char* value = std::getenv("PORT");

    if (value == nullptr)
    {
        return 5001;
    }

    try
    {
        return std::stoi(value);
    }
    catch (...)
    {
        return 5001;
    }
}
}

int main()
{
    app().registerHandler(
        "/health",
        [](
            const HttpRequestPtr&,
            std::function<void(
                const HttpResponsePtr&
            )>&& callback
        )
        {
            Json::Value result;

            result["service"] =
                "WebHawk Vulnerable Backend C++";

            result["status"] = "ok";

            callback(jsonResponse(result));
        },
        {Get}
    );

    app().registerHandler(
        "/products",
        [](
            const HttpRequestPtr& request,
            std::function<void(
                const HttpResponsePtr&
            )>&& callback
        )
        {
            Json::Value products(
                Json::arrayValue
            );

            Json::Value laptop;
            laptop["id"] = 1;
            laptop["name"] = "Laptop";
            laptop["price"] = 1200;
            laptop["category"] = "computers";

            Json::Value phone;
            phone["id"] = 2;
            phone["name"] = "Phone";
            phone["price"] = 800;
            phone["category"] = "phones";

            products.append(laptop);
            products.append(phone);

            Json::Value result;

            result["message"] =
                "Products returned from vulnerable backend";

            result["category"] =
                request->getParameter("category");

            result["products"] = products;

            callback(jsonResponse(result));
        },
        {Get}
    );

    app().registerHandler(
        "/search",
        [](
            const HttpRequestPtr& request,
            std::function<void(
                const HttpResponsePtr&
            )>&& callback
        )
        {
            Json::Value result;

            result["message"] =
                "Search executed without security checks";

            result["query"] =
                request->getParameter("q");

            Json::Value matches(
                Json::arrayValue
            );

            matches.append("Laptop");
            matches.append("Phone");

            result["results"] = matches;

            callback(jsonResponse(result));
        },
        {Get}
    );

    app().registerHandler(
        "/comments",
        [](
            const HttpRequestPtr& request,
            std::function<void(
                const HttpResponsePtr&
            )>&& callback
        )
        {
            const auto body =
                request->getJsonObject();

            if (
                body == nullptr
                || !body->isMember("comment")
                || !(*body)["comment"].isString()
            )
            {
                Json::Value error;
                error["error"] =
                    "comment is required";

                callback(
                    jsonResponse(
                        error,
                        k400BadRequest
                    )
                );

                return;
            }

            Json::Value result;

            result["message"] =
                "Comment stored without security checks";

            result["comment"] =
                (*body)["comment"].asString();

            callback(
                jsonResponse(
                    result,
                    k201Created
                )
            );
        },
        {Post}
    );

    app().registerHandler(
        "/login",
        [](
            const HttpRequestPtr& request,
            std::function<void(
                const HttpResponsePtr&
            )>&& callback
        )
        {
            const auto body =
                request->getJsonObject();

            if (
                body == nullptr
                || !body->isMember("username")
                || !body->isMember("password")
            )
            {
                Json::Value error;

                error["error"] =
                    "username and password are required";

                callback(
                    jsonResponse(
                        error,
                        k400BadRequest
                    )
                );

                return;
            }

            Json::Value result;

            result["message"] =
                "Credentials received by vulnerable backend";

            result["username"] =
                (*body)["username"].asString();

            result["authenticated"] = true;

            callback(jsonResponse(result));
        },
        {Post}
    );

    const int port = serverPort();

    LOG_INFO
        << "Vulnerable C++ backend listening on port "
        << port;

    app()
        .addListener("0.0.0.0", port)
        .setThreadNum(2)
        .run();

    return 0;
}