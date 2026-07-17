#include "repositories/SessionRepository.h"

#include "database/Database.h"

#include <pqxx/pqxx>

using namespace webhawk::repositories;

namespace
{
template <typename RowType>
webhawk::models::UserSession rowToSession(
    const RowType& row
)
{
    webhawk::models::UserSession session;

    session.id = row["id"].template as<int>();
    session.userId = row["user_id"].template as<int>();
    session.tokenHash = row["token_hash"].template as<std::string>();
    session.ipAddress = row["ip_address"].template as<std::string>();
    session.createdAt = row["created_at"].template as<std::string>();
    session.expiresAt = row["expires_at"].template as<std::string>();
    session.isActive = row["is_active"].template as<bool>();

    return session;
}
}

int SessionRepository::countSessions()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM user_sessions"
    );
}

webhawk::models::UserSession SessionRepository::createSession(
    int userId,
    const std::string& tokenHash,
    const std::string& ipAddress,
    std::int64_t expiresAt
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "INSERT INTO user_sessions "
        "(user_id, token_hash, ip_address, expires_at) "
        "VALUES ($1, $2, $3, TO_TIMESTAMP($4)) "
        "RETURNING id, user_id, token_hash, ip_address, "
        "created_at, expires_at, is_active",
        userId,
        tokenHash,
        ipAddress,
        expiresAt
    );

    transaction.commit();

    return rowToSession(result[0]);
}

std::optional<webhawk::models::UserSession>
SessionRepository::findActiveByTokenHash(
    const std::string& tokenHash
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT id, user_id, token_hash, ip_address, "
        "created_at, expires_at, is_active "
        "FROM user_sessions "
        "WHERE token_hash = $1 "
        "AND is_active = TRUE "
        "AND expires_at > NOW()",
        tokenHash
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToSession(result[0]);
}

std::vector<webhawk::models::UserSession>
SessionRepository::findActiveByUserId(
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT id, user_id, token_hash, ip_address, "
        "created_at, expires_at, is_active "
        "FROM user_sessions "
        "WHERE user_id = $1 "
        "AND is_active = TRUE "
        "AND expires_at > NOW() "
        "ORDER BY created_at DESC",
        userId
    );

    transaction.commit();

    std::vector<webhawk::models::UserSession> sessions;
    sessions.reserve(result.size());

    for (const auto& row : result)
    {
        sessions.push_back(rowToSession(row));
    }

    return sessions;
}

bool SessionRepository::deactivateByTokenHash(
    const std::string& tokenHash
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "UPDATE user_sessions "
        "SET is_active = FALSE "
        "WHERE token_hash = $1 "
        "AND is_active = TRUE "
        "RETURNING id",
        tokenHash
    );

    transaction.commit();

    return !result.empty();
}
