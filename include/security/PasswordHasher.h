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

    static bool verifyPassword(
        const std::string& password,
        const std::string& storedHash
    );

private:
    static std::string generateSalt();
    static std::string deriveHash(
        const std::string& password,
        const std::string& saltHex,
        int iterations
    );
    static std::string toHex(
        const unsigned char* data,
        int length
    );
};
}
