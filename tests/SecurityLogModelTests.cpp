#include "models/SecurityLog.h"

#include <cstdlib>
#include <iostream>

int main()
{
    webhawk::models::SecurityLog log;

    log.id = 7;
    log.backendId = 2;
    log.ipAddress = "203.0.113.10";
    log.method = "GET";
    log.endpoint = "/products";
    log.attackType = "SQL_INJECTION";
    log.isBlocked = true;

    log.requestData =
        R"({"query":{"id":"attack"}})";

    log.createdAt =
        "2026-07-28 12:00:00+00";

    const Json::Value json =
        log.toJson();

    if (
        json["id"].asInt() != 7
        || !json["is_blocked"].asBool()
        || json["request_data"]
            ["query"]
            ["id"].asString() != "attack"
    )
    {
        std::cerr
            << "FAILED: SecurityLog "
            << "JSON serialization\n";

        return EXIT_FAILURE;
    }

    std::cout
        << "All security log model "
        << "tests passed\n";

    return EXIT_SUCCESS;
}