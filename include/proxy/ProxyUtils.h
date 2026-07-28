#pragma once

#include <optional>
#include <string>

namespace webhawk::proxy
{
struct ParsedProxyPath
{
    std::string apiKey;
    std::string targetPath;
};

struct ParsedTargetUrl
{
    std::string origin;
    std::string basePath;
};

class ProxyUtils
{
public:
    static std::optional<ParsedProxyPath>
    parseProxyPath(
        const std::string& path
    );

    static std::optional<ParsedTargetUrl>
    parseTargetUrl(
        const std::string& url
    );

    static std::string joinPaths(
        const std::string& basePath,
        const std::string& requestPath
    );

    static bool isHopByHopHeader(
        const std::string& headerName
    );

    static bool isSensitiveHeader(
        const std::string& headerName
    );

    static std::string lowercase(
        std::string value
    );
};
}