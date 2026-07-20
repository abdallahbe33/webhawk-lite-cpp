#include "security/SqlInjectionDetector.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

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
    const std::vector<std::string> maliciousInputs = {
        "' OR 1=1 --",
        "admin' OR 'x'='x' #",
        "1 UNION SELECT username, password FROM users",
        "1 UNION ALL SELECT NULL, version()",
        "1; DROP TABLE users; --",
        "1; DELETE FROM users",
        "INSERT INTO users(name) VALUES('attacker')",
        "UPDATE users SET password='hacked'",
        "' AND SLEEP(5) --",
        "1 WAITFOR DELAY '00:00:05'",
        "SELECT * FROM information_schema.tables",
        "%27%20OR%201%3D1%20--",
        "%2527%2520OR%25201%253D1%2520--",
        "1 un/**/ion select password from users"
    };

    for (const auto& input : maliciousInputs)
    {
        const auto result =
            webhawk::security::SqlInjectionDetector::scan(
                input
            );

        require(
            result.detected,
            "Expected SQL injection detection for: "
                + input
        );

        require(
            result.attackType == "SQL_INJECTION",
            "Expected SQL_INJECTION attack type"
        );

        require(
            !result.ruleId.empty(),
            "Expected a detector rule ID"
        );
    }

    const std::vector<std::string> safeInputs = {
        "phones",
        "john@example.com",
        "The Union Jack shirt is blue",
        "Please select a product from the catalog",
        "Order number 1001",
        "/products/42",
        "Nothing dangerous here"
    };

    for (const auto& input : safeInputs)
    {
        const auto result =
            webhawk::security::SqlInjectionDetector::scan(
                input
            );

        require(
            !result.detected,
            "Expected safe input for: " + input
        );
    }

    std::cout
        << "All SQL injection detector tests passed\n";

    return 0;
}