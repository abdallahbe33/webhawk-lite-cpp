#pragma once

#include <string>

namespace webhawk::security
{
class PasswordHasher
{
public:
    static std::string hashPassword(
        const std::string& password
    );

private:
    static std::string generateSalt();
    static std::string toHex(
        const unsigned char* data,
        int length
    );
};
}