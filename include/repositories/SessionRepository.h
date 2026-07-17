#pragma once

#include "models/UserSession.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace webhawk::repositories
{
class SessionRepository
{
public:
    static int countSessions();

    static webhawk::models::UserSession createSession(
        int userId,
        const std::string& tokenHash,
        const std::string& ipAddress,
        std::int64_t expiresAt
    );

    static std::optional<webhawk::models::UserSession>
    findActiveByTokenHash(
        const std::string& tokenHash
    );

    static std::vector<webhawk::models::UserSession>
    findActiveByUserId(
        int userId
    );

    static bool deactivateByTokenHash(
        const std::string& tokenHash
    );
};
}
