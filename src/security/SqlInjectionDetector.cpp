#include "security/SqlInjectionDetector.h"

#include <algorithm>
#include <cctype>
#include <regex>
#include <string>
#include <vector>

using namespace webhawk::security;

namespace
{
struct SqlRule
{
    std::string id;
    std::regex pattern;
    std::string description;
    int riskScore;
};

const std::vector<SqlRule>& rules()
{
    static const std::vector<SqlRule> sqlRules = {
        {
            "SQLI_001",
            std::regex(
                R"(\bunion(?:\s+all)?\s+select\b)",
                std::regex::icase
            ),
            "UNION SELECT query detected",
            95
        },
        {
            "SQLI_002",
            std::regex(
                R"((^|[\s'\"])(or|and)\s+[0-9]+\s*=\s*[0-9]+)",
                std::regex::icase
            ),
            "Boolean SQL tautology detected",
            90
        },
        {
            "SQLI_003",
            std::regex(
                R"((^|[\s'\"])(or|and)\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"])",
                std::regex::icase
            ),
            "String-based SQL tautology detected",
            90
        },
        {
            "SQLI_004",
            std::regex(
                R"(;\s*(select|insert|update|delete|drop|alter|create|truncate|exec|execute)\b)",
                std::regex::icase
            ),
            "Stacked SQL statement detected",
            95
        },
        {
            "SQLI_005",
            std::regex(
                R"(\bdrop\s+(table|database|schema)\b)",
                std::regex::icase
            ),
            "Destructive DROP statement detected",
            100
        },
        {
            "SQLI_006",
            std::regex(
                R"(\binsert\s+into\b)",
                std::regex::icase
            ),
            "INSERT statement detected",
            85
        },
        {
            "SQLI_007",
            std::regex(
                R"(\bdelete\s+from\b)",
                std::regex::icase
            ),
            "DELETE statement detected",
            90
        },
        {
            "SQLI_008",
            std::regex(
                R"(\bupdate\s+[a-z0-9_.\"]+\s+set\b)",
                std::regex::icase
            ),
            "UPDATE statement detected",
            85
        },
        {
            "SQLI_009",
            std::regex(
                R"(\b(sleep|pg_sleep|benchmark)\s*\()",
                std::regex::icase
            ),
            "Time-based SQL injection function detected",
            95
        },
        {
            "SQLI_010",
            std::regex(
                R"(\bwaitfor\s+delay\b)",
                std::regex::icase
            ),
            "Time-based WAITFOR DELAY attack detected",
            95
        },
        {
            "SQLI_011",
            std::regex(
                R"(\binformation_schema\b)",
                std::regex::icase
            ),
            "Database schema discovery detected",
            90
        },
        {
            "SQLI_012",
            std::regex(
                R"(\b(xp_cmdshell|load_file)\s*\()",
                std::regex::icase
            ),
            "Dangerous database function detected",
            100
        },
        {
            "SQLI_013",
            std::regex(
                R"(\binto\s+(outfile|dumpfile)\b)",
                std::regex::icase
            ),
            "Database file-write attempt detected",
            100
        },
        {
            "SQLI_014",
            std::regex(
                R"(['\"]\s*(--|#))",
                std::regex::icase
            ),
            "Quote followed by SQL comment detected",
            80
        }
    };

    return sqlRules;
}
}

int SqlInjectionDetector::hexValue(char character)
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

    if (character >= 'a' && character <= 'f')
    {
        return character - 'a' + 10;
    }

    return -1;
}

std::string SqlInjectionDetector::urlDecode(
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

std::string SqlInjectionDetector::normalize(
    const std::string& value
)
{
    // Decode twice to catch double-encoded attacks.
    std::string normalized = urlDecode(
        urlDecode(value)
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

    // Remove null bytes that attackers may use for evasion.
    normalized.erase(
        std::remove(
            normalized.begin(),
            normalized.end(),
            '\0'
        ),
        normalized.end()
    );

    // Remove inline comments such as:
    // un/**/ion select
    static const std::regex inlineComment(
        R"(/\*[^*]*\*+(?:[^/*][^*]*\*+)*/)",
        std::regex::icase
    );

    normalized = std::regex_replace(
        normalized,
        inlineComment,
        ""
    );

    // Convert multiple spaces, tabs, and newlines to one space.
    static const std::regex whitespace(R"(\s+)");

    normalized = std::regex_replace(
        normalized,
        whitespace,
        " "
    );

    return normalized;
}

DetectionResult SqlInjectionDetector::scan(
    const std::string& value
)
{
    if (value.empty())
    {
        return {};
    }

    const std::string normalizedValue = normalize(value);

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
            result.attackType = "SQL_INJECTION";
            result.ruleId = rule.id;
            result.matchedPattern = match.str();
            result.message = rule.description;
            result.riskScore = rule.riskScore;

            return result;
        }
    }

    return {};
}