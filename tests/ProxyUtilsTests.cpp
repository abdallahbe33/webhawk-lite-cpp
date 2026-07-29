#include "proxy/ProxyUtils.h"

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
        std::cerr
            << "FAILED: "
            << message
            << '\n';

        std::exit(1);
    }
}
}

int main()
{
    using webhawk::proxy::ProxyUtils;

    const auto path =
        ProxyUtils::parseProxyPath(
            "/proxy/webhawk_abc/products/42"
        );

    require(
        path.has_value(),
        "Expected a valid proxy path"
    );

    require(
        path->apiKey == "webhawk_abc",
        "Expected API key extraction"
    );

    require(
        path->targetPath == "/products/42",
        "Expected nested target path"
    );

    const auto root =
        ProxyUtils::parseProxyPath(
            "/proxy/webhawk_abc"
        );

    require(
        root.has_value()
            && root->targetPath == "/",
        "Expected root target path"
    );

    require(
        !ProxyUtils::parseProxyPath(
            "/proxy/"
        ).has_value(),
        "Empty API key must fail"
    );

    const auto target =
        ProxyUtils::parseTargetUrl(
            "http://localhost:5001/api/"
        );

    require(
        target.has_value(),
        "Expected valid target URL"
    );

    require(
        target->origin
            == "http://localhost:5001",
        "Expected target origin"
    );

    require(
        target->basePath == "/api",
        "Expected normalized base path"
    );

    require(
        ProxyUtils::joinPaths(
            target->basePath,
            "/products"
        ) == "/api/products",
        "Expected joined target path"
    );

    require(
        ProxyUtils::isHopByHopHeader(
            "Connection"
        ),
        "Connection header must not be forwarded"
    );

    require(
        !ProxyUtils::isHopByHopHeader(
            "Content-Type"
        ),
        "Content-Type must be forwarded"
    );

    require(
        ProxyUtils::isSensitiveHeader(
            "Authorization"
        ),
        "Authorization must be redacted"
    );

    std::cout
        << "All proxy utility tests passed\n";

    return EXIT_SUCCESS;
}
