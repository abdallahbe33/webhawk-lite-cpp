#include "security/XssDetector.h"

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
        "<script>alert(1)</script>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "java/**/script:alert(1)",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;script&#x3e;alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<input autofocus onfocus=alert(1)>",
        "document.cookie",
        "data:text/html,<script>alert(1)</script>"
    };

    for (const auto& input : maliciousInputs)
    {
        const auto result =
            webhawk::security::XssDetector::scan(
                input
            );

        require(
            result.detected,
            "Expected XSS detection for: " + input
        );

        require(
            result.attackType == "XSS",
            "Expected XSS attack type"
        );

        require(
            !result.ruleId.empty(),
            "Expected an XSS detector rule ID"
        );
    }

    const std::vector<std::string> safeInputs = {
        "A script writing tutorial",
        "The JavaScript programming language",
        "The onclick event is documented",
        "image.png",
        "<p>Hello world</p>",
        "contact@example.com",
        "/comments/42"
    };

    for (const auto& input : safeInputs)
    {
        require(
            !webhawk::security::XssDetector::
                scan(input).detected,
            "Expected safe input for: " + input
        );
    }

    std::cout
        << "All XSS detector tests passed\n";

    return 0;
}