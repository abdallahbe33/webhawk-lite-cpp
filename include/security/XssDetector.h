#pragma once

#include "security/DetectionResult.h"

#include <string>

namespace webhawk::security
{
class XssDetector
{
public:
    static DetectionResult scan(const std::string& value);

private:
    static std::string normalize(const std::string& value);
    static std::string urlDecode(const std::string& value);
    static std::string htmlEntityDecode(const std::string& value);
    static int hexValue(char character);
};
}