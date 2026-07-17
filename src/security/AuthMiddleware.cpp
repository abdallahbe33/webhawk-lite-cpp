#include "security/AuthMiddleware.h"

#include "repositories/SessionRepository.h"

using namespace webhawk::security;

std::string AuthMiddleware::extractBearerToken(
    const std::string& authorizationHeader
)
{
    static const std::string prefix = "Bearer ";

    if (
        authorizationHeader.size() <= prefix.size()
        || authorizationHeader.compare(
            0,
            prefix.size(),
            prefix
        ) != 0
    )
    {
        return "";
    }

    return authorizationHeader.substr(prefix.size());
}

AuthenticationResult AuthMiddleware::authenticate(
    const std::string& authorizationHeader
)
{
    const std::string token = extractBearerToken(
        authorizationHeader
    );

    if (token.empty())
    {
        return {
            false,
            401,
            "Bearer token is required",
            {}
        };
    }

    const auto claims = JwtService::validateToken(token);

    if (!claims.has_value())
    {
        return {
            false,
            401,
            "Token is invalid or expired",
            {}
        };
    }

    const std::string tokenHash = JwtService::hashToken(token);

    const auto session =
        webhawk::repositories::SessionRepository::findActiveByTokenHash(
            tokenHash
        );

    if (
        !session.has_value()
        || session->userId != claims->userId
    )
    {
        return {
            false,
            401,
            "Session is inactive or expired",
            {}
        };
    }

    AuthContext context;
    context.userId = claims->userId;
    context.token = token;
    context.tokenHash = tokenHash;
    context.claims = claims.value();
    context.session = session.value();

    return {
        true,
        200,
        "Authenticated",
        context
    };
}
