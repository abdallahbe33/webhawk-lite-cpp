#include "proxy/ProxyUtils.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <unordered_set>

using namespace webhawk::proxy;

std::string ProxyUtils::lowercase(
    std::string value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char character)
        {
            return static_cast<char>(
                std::tolower(character)
            );
        }
    );

    return value;
}

std::optional<ParsedProxyPath>
ProxyUtils::parseProxyPath(
    const std::string& path
)
{
    const std::string prefix =
        "/proxy/";

    if (path.rfind(prefix, 0) != 0)
    {
        return std::nullopt;
    }

    const std::string remainder =
        path.substr(prefix.size());

    if (remainder.empty())
    {
        return std::nullopt;
    }

    const auto slash =
        remainder.find('/');

    ParsedProxyPath parsed;

    parsed.apiKey =
        slash == std::string::npos
            ? remainder
            : remainder.substr(
                0,
                slash
            );

    parsed.targetPath =
        slash == std::string::npos
            ? "/"
            : remainder.substr(slash);

    if (
        parsed.apiKey.empty()
        || parsed.targetPath.empty()
    )
    {
        return std::nullopt;
    }

    return parsed;
}

std::optional<ParsedTargetUrl>
ProxyUtils::parseTargetUrl(
    const std::string& url
)
{
    static const std::regex pattern(
        R"(^(https?://[^/]+)(/.*)?$)",
        std::regex::icase
    );

    std::smatch match;

    if (!std::regex_match(
        url,
        match,
        pattern
    ))
    {
        return std::nullopt;
    }

    ParsedTargetUrl parsed;

    parsed.origin =
        match[1].str();

    parsed.basePath =
        match[2].matched
            ? match[2].str()
            : "";

    while (
        parsed.basePath.size() > 1
        && parsed.basePath.back() == '/'
    )
    {
        parsed.basePath.pop_back();
    }

    return parsed;
}

std::string ProxyUtils::joinPaths(
    const std::string& basePath,
    const std::string& requestPath
)
{
    std::string left = basePath;

    std::string right =
        requestPath.empty()
            ? "/"
            : requestPath;

    while (
        left.size() > 1
        && left.back() == '/'
    )
    {
        left.pop_back();
    }

    if (right.front() != '/')
    {
        right.insert(
            right.begin(),
            '/'
        );
    }

    if (
        left.empty()
        || left == "/"
    )
    {
        return right;
    }

    return left + right;
}

bool ProxyUtils::isHopByHopHeader(
    const std::string& headerName
)
{
    static const std::unordered_set<
        std::string
    > blockedHeaders = {
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-webhawk-backend-id"
    };

    const std::string normalizedName =
        lowercase(headerName);

    return blockedHeaders.find(
        normalizedName
    ) != blockedHeaders.end();
}

bool ProxyUtils::isSensitiveHeader(
    const std::string& headerName
)
{
    const std::string name =
        lowercase(headerName);

    return name == "authorization"
        || name == "cookie"
        || name == "proxy-authorization"
        || name == "x-api-key";
}
