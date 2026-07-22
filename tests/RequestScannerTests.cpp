#include "security/RequestScanner.h"

#include <cstdlib>
#include <iostream>
#include <string>

namespace
{
void require(
    bool condition,
    const std::string& message
)
{
    if (!condition)
    {
        std::cerr << "FAILED: " << message << '\n';
        std::exit(1);
    }
}
}

int main()
{
    Json::Value safe;
    safe["path"] = "/products";
    safe["query"]["category"] = "phones";
    safe["body"]["comment"] = "Great product";
    safe["headers"]["Accept"] = "application/json";

    require(
        webhawk::security::RequestScanner::
            scan(safe).allowed,
        "Expected safe request data"
    );

    Json::Value sqlAttack = safe;
    sqlAttack["query"]["id"] = "' OR 1=1 --";

    const auto sqlResult =
        webhawk::security::RequestScanner::scan(
            sqlAttack
        );

    require(
        !sqlResult.allowed,
        "Expected SQL injection to be blocked"
    );

    require(
        sqlResult.detection.attackType
            == "SQL_INJECTION",
        "Expected SQL attack type"
    );

    require(
        sqlResult.field == "query.id",
        "Expected query.id field location"
    );

    Json::Value xssAttack = safe;

    xssAttack["body"]["comment"] =
        "<script>alert(1)</script>";

    const auto xssResult =
        webhawk::security::RequestScanner::scan(
            xssAttack
        );

    require(
        !xssResult.allowed,
        "Expected XSS to be blocked"
    );

    require(
        xssResult.detection.attackType == "XSS",
        "Expected XSS attack type"
    );

    require(
        xssResult.field == "body.comment",
        "Expected body.comment field location"
    );

    Json::Value arrayAttack;

    arrayAttack["body"]["tags"].append("safe");

    arrayAttack["body"]["tags"].append(
        "<img src=x onerror=alert(1)>"
    );

    const auto arrayResult =
        webhawk::security::RequestScanner::scan(
            arrayAttack
        );

    require(
        !arrayResult.allowed,
        "Expected nested array XSS to be blocked"
    );

    require(
        arrayResult.field == "body.tags[1]",
        "Expected array field location"
    );

    const auto sqlOnly =
        webhawk::security::RequestScanner::
            scanSqlInjection(xssAttack);

    require(
        sqlOnly.allowed,
        "SQL-only route must not report XSS"
    );

    std::cout
        << "All combined request scanner tests passed\n";

    return 0;
}