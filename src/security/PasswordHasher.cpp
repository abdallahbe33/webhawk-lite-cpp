#include "security/PasswordHasher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

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

    return "pbkdf2_sha256$"
        + std::to_string(ITERATIONS)
        + "$"
        + saltHex
        + "$"
        + deriveHash(password, saltHex, ITERATIONS);
}

std::string PasswordHasher::deriveHash(
    const std::string& password,
    const std::string& saltHex,
    int iterations
)
{
    std::vector<unsigned char> hash(HASH_SIZE);

    if (
        PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            reinterpret_cast<const unsigned char*>(saltHex.c_str()),
            static_cast<int>(saltHex.size()),
            iterations,
            EVP_sha256(),
            HASH_SIZE,
            hash.data()
        ) != 1
    )
    {
        throw std::runtime_error("Failed to hash password");
    }

    return toHex(hash.data(), HASH_SIZE);
}

bool PasswordHasher::verifyPassword(
    const std::string& password,
    const std::string& storedHash
)
{
    const std::size_t firstSeparator = storedHash.find('$');
    const std::size_t secondSeparator = storedHash.find(
        '$',
        firstSeparator + 1
    );
    const std::size_t thirdSeparator = storedHash.find(
        '$',
        secondSeparator + 1
    );

    if (
        firstSeparator == std::string::npos
        || secondSeparator == std::string::npos
        || thirdSeparator == std::string::npos
        || storedHash.substr(0, firstSeparator) != "pbkdf2_sha256"
    )
    {
        return false;
    }

    try
    {
        const int iterations = std::stoi(
            storedHash.substr(
                firstSeparator + 1,
                secondSeparator - firstSeparator - 1
            )
        );

        const std::string saltHex = storedHash.substr(
            secondSeparator + 1,
            thirdSeparator - secondSeparator - 1
        );

        const std::string expectedHash = storedHash.substr(
            thirdSeparator + 1
        );

        const std::string actualHash = deriveHash(
            password,
            saltHex,
            iterations
        );

        return expectedHash.size() == actualHash.size()
            && CRYPTO_memcmp(
                expectedHash.data(),
                actualHash.data(),
                expectedHash.size()
            ) == 0;
    }
    catch (...)
    {
        return false;
    }
}
