#include "security/XssDetector.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <vector>

using namespace webhawk::security;

namespace
{
struct XssRule
{
    std::string id;
    std::regex pattern;
    std::string description;
    int riskScore;
};

const std::vector<XssRule>& rules()
{
    static const std::vector<XssRule> xssRules = {
        {
            "XSS_001",
            std::regex(
                R"(<\s*script\b)",
                std::regex::icase
            ),
            "Script element detected",
            100
        },
        {
            "XSS_002",
            std::regex(
                R"(<\s*/\s*script\s*>)",
                std::regex::icase
            ),
            "Closing script element detected",
            95
        },
        {
            "XSS_003",
            std::regex(
                R"(javascript\s*:)",
                std::regex::icase
            ),
            "JavaScript URI detected",
            95
        },
        {
            "XSS_004",
            std::regex(
                R"(vbscript\s*:)",
                std::regex::icase
            ),
            "VBScript URI detected",
            95
        },
        {
            "XSS_005",
            std::regex(
                R"(data\s*:\s*text/html)",
                std::regex::icase
            ),
            "Executable data URI detected",
            90
        },
        {
            "XSS_006",
            std::regex(
                R"(\bon(error|load|click|mouseover|focus|blur|submit|change|input|animationstart|pointerover|toggle)\s*=)",
                std::regex::icase
            ),
            "Inline event handler detected",
            90
        },
        {
            "XSS_007",
            std::regex(
                R"(<\s*(iframe|object|embed|svg|math|meta|style)\b)",
                std::regex::icase
            ),
            "Dangerous HTML element detected",
            85
        },
        {
            "XSS_008",
            std::regex(
                R"(\bsrcdoc\s*=)",
                std::regex::icase
            ),
            "HTML srcdoc attribute detected",
            90
        },
        {
            "XSS_009",
            std::regex(
                R"(\bexpression\s*\()",
                std::regex::icase
            ),
            "CSS expression detected",
            90
        },
        {
            "XSS_010",
            std::regex(
                R"(\b(document|window)\s*\.\s*(cookie|location|open)\b)",
                std::regex::icase
            ),
            "Browser object access detected",
            85
        },
        {
            "XSS_011",
            std::regex(
                R"(\b(eval|settimeout|setinterval)\s*\()",
                std::regex::icase
            ),
            "Dynamic JavaScript execution detected",
            85
        }
    };

    return xssRules;
}
}

int XssDetector::hexValue(char character)
{
    if (character >= '0' && character <= '9')
    {
        return character - '0';
    }

    character = static_cast<char>(
        std::tolower(
            static_cast<unsigned char>(character)
        )
    );

    return character >= 'a' && character <= 'f'
        ? character - 'a' + 10
        : -1;
}

std::string XssDetector::urlDecode(
    const std::string& value
)
{
    std::string decoded;
    decoded.reserve(value.size());

    for (
        std::size_t index = 0;
        index < value.size();
        ++index
    )
    {
        if (value[index] == '+')
        {
            decoded.push_back(' ');
            continue;
        }

        if (
            value[index] == '%'
            && index + 2 < value.size()
        )
        {
            const int high = hexValue(value[index + 1]);
            const int low = hexValue(value[index + 2]);

            if (high >= 0 && low >= 0)
            {
                decoded.push_back(
                    static_cast<char>((high << 4) | low)
                );

                index += 2;
                continue;
            }
        }

        decoded.push_back(value[index]);
    }

    return decoded;
}

std::string XssDetector::htmlEntityDecode(
    const std::string& value
)
{
    std::string decoded;
    decoded.reserve(value.size());

    for (
        std::size_t index = 0;
        index < value.size();
        ++index
    )
    {
        if (value[index] != '&')
        {
            decoded.push_back(value[index]);
            continue;
        }

        const auto end = value.find(';', index + 1);

        if (
            end == std::string::npos
            || end - index > 12
        )
        {
            decoded.push_back(value[index]);
            continue;
        }

        std::string entity =
            value.substr(index + 1, end - index - 1);

        std::transform(
            entity.begin(),
            entity.end(),
            entity.begin(),
            [](unsigned char character)
            {
                return static_cast<char>(
                    std::tolower(character)
                );
            }
        );

        int code = -1;

        if (entity == "lt")
        {
            code = '<';
        }
        else if (entity == "gt")
        {
            code = '>';
        }
        else if (entity == "quot")
        {
            code = '"';
        }
        else if (
            entity == "apos"
            || entity == "#39"
        )
        {
            code = '\'';
        }
        else if (entity == "colon")
        {
            code = ':';
        }
        else if (entity == "tab")
        {
            code = '\t';
        }
        else if (entity == "newline")
        {
            code = '\n';
        }
        else if (entity == "amp")
        {
            code = '&';
        }
        else if (
            entity.size() > 1
            && entity[0] == '#'
        )
        {
            try
            {
                const bool hexadecimal =
                    entity.size() > 2
                    && entity[1] == 'x';

                const std::string digits =
                    entity.substr(
                        hexadecimal ? 2 : 1
                    );

                code = std::stoi(
                    digits,
                    nullptr,
                    hexadecimal ? 16 : 10
                );
            }
            catch (...)
            {
                code = -1;
            }
        }

        if (code >= 0 && code <= 127)
        {
            decoded.push_back(
                static_cast<char>(code)
            );

            index = end;
        }
        else
        {
            decoded.push_back(value[index]);
        }
    }

    return decoded;
}

std::string XssDetector::normalize(
    const std::string& value
)
{
    // Decode twice to detect double-encoded payloads.
    std::string normalized = urlDecode(
        urlDecode(value)
    );

    normalized = htmlEntityDecode(
        htmlEntityDecode(normalized)
    );

    std::transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char character)
        {
            return static_cast<char>(
                std::tolower(character)
            );
        }
    );

    normalized.erase(
        std::remove(
            normalized.begin(),
            normalized.end(),
            '\0'
        ),
        normalized.end()
    );

    // Detect payloads such as java/**/script.
    static const std::regex inlineComment(
        R"(/\*[^*]*\*+(?:[^/*][^*]*\*+)*/)",
        std::regex::icase
    );

    normalized = std::regex_replace(
        normalized,
        inlineComment,
        ""
    );

    static const std::regex whitespace(R"(\s+)");

    return std::regex_replace(
        normalized,
        whitespace,
        " "
    );
}

DetectionResult XssDetector::scan(
    const std::string& value
)
{
    if (value.empty())
    {
        return {};
    }

    const std::string normalizedValue =
        normalize(value);

    for (const auto& rule : rules())
    {
        std::smatch match;

        if (
            std::regex_search(
                normalizedValue,
                match,
                rule.pattern
            )
        )
        {
            DetectionResult result;
            result.detected = true;
            result.attackType = "XSS";
            result.ruleId = rule.id;
            result.matchedPattern = match.str();
            result.message = rule.description;
            result.riskScore = rule.riskScore;

            return result;
        }
    }

    return {};
}