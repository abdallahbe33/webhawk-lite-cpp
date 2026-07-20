#pragma once

#include <json/json.h>
#include <string>

namespace webhawk::security
{
struct DetectionResult
{
    bool detected{};
    std::string attackType{"NONE"};
    std::string ruleId;
    std::string matchedPattern;
    std::string message{"No attack detected"};
    int riskScore{};

    Json::Value toJson() const
    {
        Json::Value value;

        value["detected"] = detected;
        value["attack_type"] = attackType;
        value["rule_id"] = ruleId;
        value["matched_pattern"] = matchedPattern;
        value["message"] = message;
        value["risk_score"] = riskScore;

        return value;
    }
};
}