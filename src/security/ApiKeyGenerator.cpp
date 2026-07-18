#include "security/ApiKeyGenerator.h"

#include <openssl/rand.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

using namespace webhawk::security;

namespace
{
constexpr int API_KEY_RANDOM_BYTES = 24;
}

std::string ApiKeyGenerator::toHex(
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

std::string ApiKeyGenerator::generate()
{
    unsigned char randomBytes[API_KEY_RANDOM_BYTES];

    if (
        RAND_bytes(
            randomBytes,
            API_KEY_RANDOM_BYTES
        ) != 1
    )
    {
        throw std::runtime_error("Failed to generate API key");
    }

    return "webhawk_" + toHex(
        randomBytes,
        API_KEY_RANDOM_BYTES
    );
}