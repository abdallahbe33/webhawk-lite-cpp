#include "security/PasswordHasher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace webhawk::security;

namespace
{
constexpr int SALT_SIZE = 16;
constexpr int HASH_SIZE = 32;
constexpr int ITERATIONS = 100000;
}

std::string PasswordHasher::toHex(
    const unsigned char* data,
    int length
)
{
    std::ostringstream stream;

    for (int index = 0; index < length; ++index)
    {
        stream << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(data[index]);
    }

    return stream.str();
}

std::string PasswordHasher::generateSalt()
{
    std::vector<unsigned char> salt(SALT_SIZE);

    if (RAND_bytes(salt.data(), SALT_SIZE) != 1)
    {
        throw std::runtime_error("Failed to generate password salt");
    }

    return toHex(
        salt.data(),
        SALT_SIZE
    );
}

std::string PasswordHasher::hashPassword(
    const std::string& password
)
{
    const std::string saltHex = generateSalt();

    std::vector<unsigned char> hash(HASH_SIZE);

    if (
        PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            reinterpret_cast<const unsigned char*>(saltHex.c_str()),
            static_cast<int>(saltHex.size()),
            ITERATIONS,
            EVP_sha256(),
            HASH_SIZE,
            hash.data()
        ) != 1
    )
    {
        throw std::runtime_error("Failed to hash password");
    }

    return "pbkdf2_sha256$"
        + std::to_string(ITERATIONS)
        + "$"
        + saltHex
        + "$"
        + toHex(hash.data(), HASH_SIZE);
}