#include "security/JwtService.h"

#include "config/AppConfig.h"

#include <json/json.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

using namespace webhawk::security;

namespace
{
std::string writeJson(
    const Json::Value& value
)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    return Json::writeString(builder, value);
}

std::optional<Json::Value> parseJson(
    const std::string& value
)
{
    Json::CharReaderBuilder builder;
    Json::Value json;
    std::string errors;
    std::istringstream stream(value);

    if (!Json::parseFromStream(builder, stream, &json, &errors))
    {
        return std::nullopt;
    }

    return json;
}
}

std::string JwtService::toHex(
    const unsigned char* data,
    std::size_t length
)
{
    std::ostringstream stream;

    for (std::size_t index = 0; index < length; ++index)
    {
        stream << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(data[index]);
    }

    return stream.str();
}

std::string JwtService::base64UrlEncode(
    const unsigned char* data,
    std::size_t length
)
{
    std::vector<unsigned char> encoded(
        4 * ((length + 2) / 3) + 1
    );

    const int encodedLength = EVP_EncodeBlock(
        encoded.data(),
        data,
        static_cast<int>(length)
    );

    std::string result(
        reinterpret_cast<char*>(encoded.data()),
        encodedLength
    );

    std::replace(result.begin(), result.end(), '+', '-');
    std::replace(result.begin(), result.end(), '/', '_');

    while (!result.empty() && result.back() == '=')
    {
        result.pop_back();
    }

    return result;
}

std::optional<std::string> JwtService::base64UrlDecode(
    const std::string& value
)
{
    std::string padded = value;

    std::replace(padded.begin(), padded.end(), '-', '+');
    std::replace(padded.begin(), padded.end(), '_', '/');

    while (padded.size() % 4 != 0)
    {
        padded.push_back('=');
    }

    std::vector<unsigned char> decoded(
        3 * padded.size() / 4 + 1
    );

    int decodedLength = EVP_DecodeBlock(
        decoded.data(),
        reinterpret_cast<const unsigned char*>(padded.data()),
        static_cast<int>(padded.size())
    );

    if (decodedLength < 0)
    {
        return std::nullopt;
    }

    if (!padded.empty() && padded.back() == '=')
    {
        --decodedLength;
    }

    if (padded.size() > 1 && padded[padded.size() - 2] == '=')
    {
        --decodedLength;
    }

    return std::string(
        reinterpret_cast<char*>(decoded.data()),
        decodedLength
    );
}

std::string JwtService::sign(
    const std::string& value
)
{
    const std::string secret =
        webhawk::config::AppConfig::jwtSecretKey();

    unsigned int signatureLength = 0;
    unsigned char signature[EVP_MAX_MD_SIZE];

    if (
        HMAC(
            EVP_sha256(),
            secret.data(),
            static_cast<int>(secret.size()),
            reinterpret_cast<const unsigned char*>(value.data()),
            value.size(),
            signature,
            &signatureLength
        ) == nullptr
    )
    {
        throw std::runtime_error("Failed to sign JWT");
    }

    return base64UrlEncode(
        signature,
        signatureLength
    );
}

std::string JwtService::generateTokenId()
{
    unsigned char bytes[16];

    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
    {
        throw std::runtime_error("Failed to generate JWT identifier");
    }

    return toHex(bytes, sizeof(bytes));
}

CreatedJwt JwtService::createToken(
    int userId
)
{
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    JwtClaims claims;
    claims.userId = userId;
    claims.tokenId = generateTokenId();
    claims.issuedAt = now;
    claims.expiresAt = now
        + webhawk::config::AppConfig::jwtExpirationSeconds();

    Json::Value header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    Json::Value payload;
    payload["sub"] = userId;
    payload["jti"] = claims.tokenId;
    payload["iat"] = Json::Int64(claims.issuedAt);
    payload["exp"] = Json::Int64(claims.expiresAt);

    const std::string headerJson = writeJson(header);
    const std::string payloadJson = writeJson(payload);

    const std::string headerPart = base64UrlEncode(
        reinterpret_cast<const unsigned char*>(headerJson.data()),
        headerJson.size()
    );

    const std::string payloadPart = base64UrlEncode(
        reinterpret_cast<const unsigned char*>(payloadJson.data()),
        payloadJson.size()
    );

    const std::string signingInput = headerPart + "." + payloadPart;

    return {
        signingInput + "." + sign(signingInput),
        claims
    };
}

std::optional<JwtClaims> JwtService::validateToken(
    const std::string& token
)
{
    const std::size_t firstDot = token.find('.');
    const std::size_t secondDot = token.find('.', firstDot + 1);

    if (
        firstDot == std::string::npos
        || secondDot == std::string::npos
        || token.find('.', secondDot + 1) != std::string::npos
    )
    {
        return std::nullopt;
    }

    const std::string headerPart = token.substr(0, firstDot);
    const std::string payloadPart = token.substr(
        firstDot + 1,
        secondDot - firstDot - 1
    );
    const std::string signaturePart = token.substr(secondDot + 1);
    const std::string signingInput = headerPart + "." + payloadPart;
    const std::string expectedSignature = sign(signingInput);

    if (
        signaturePart.size() != expectedSignature.size()
        || CRYPTO_memcmp(
            signaturePart.data(),
            expectedSignature.data(),
            signaturePart.size()
        ) != 0
    )
    {
        return std::nullopt;
    }

    const auto decodedHeader = base64UrlDecode(headerPart);
    const auto decodedPayload = base64UrlDecode(payloadPart);

    if (!decodedHeader.has_value() || !decodedPayload.has_value())
    {
        return std::nullopt;
    }

    const auto header = parseJson(decodedHeader.value());
    const auto payload = parseJson(decodedPayload.value());

    if (
        !header.has_value()
        || !payload.has_value()
        || header->get("alg", "").asString() != "HS256"
        || !payload->isMember("sub")
        || !payload->isMember("jti")
        || !payload->isMember("iat")
        || !payload->isMember("exp")
    )
    {
        return std::nullopt;
    }

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    JwtClaims claims;
    claims.userId = (*payload)["sub"].asInt();
    claims.tokenId = (*payload)["jti"].asString();
    claims.issuedAt = (*payload)["iat"].asInt64();
    claims.expiresAt = (*payload)["exp"].asInt64();

    if (
        claims.userId <= 0
        || claims.tokenId.empty()
        || claims.issuedAt <= 0
        || claims.expiresAt <= now
        || claims.issuedAt > now + 60
    )
    {
        return std::nullopt;
    }

    return claims;
}

std::string JwtService::hashToken(
    const std::string& token
)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256(
        reinterpret_cast<const unsigned char*>(token.data()),
        token.size(),
        digest
    );

    return toHex(digest, SHA256_DIGEST_LENGTH);
}
