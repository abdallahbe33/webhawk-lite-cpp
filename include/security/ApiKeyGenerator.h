#pragma once

#include <string>

namespace webhawk::security
{
class ApiKeyGenerator
{
public:
    static std::string generate();

private:
    static std::string toHex(
        const unsigned char* data,
        int length
    );
};
}