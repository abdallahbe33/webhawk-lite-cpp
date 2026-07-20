#include "repositories/BackendRepository.h"

#include "database/Database.h"

#include <pqxx/pqxx>

using namespace webhawk::repositories;

namespace
{
template <typename RowType>
webhawk::models::BackendRegistration rowToBackend(
    const RowType& row
)
{
    webhawk::models::BackendRegistration backend;

    backend.id = row["id"].template as<int>();
    backend.userId = row["user_id"].template as<int>();
    backend.serviceName =
        row["service_name"].template as<std::string>();
    backend.targetUrl =
        row["target_url"].template as<std::string>();
    backend.apiKey =
        row["api_key"].template as<std::string>();
    backend.isActive =
        row["is_active"].template as<bool>();
    backend.createdAt =
        row["created_at"].template as<std::string>();
    backend.updatedAt =
        row["updated_at"].template as<std::string>();

    return backend;
}

const std::string BACKEND_COLUMNS =
    "id, user_id, service_name, target_url, api_key, "
    "is_active, created_at, updated_at";
}

int BackendRepository::countBackends()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM backend_registration"
    );
}

webhawk::models::BackendRegistration BackendRepository::createBackend(
    int userId,
    const std::string& serviceName,
    const std::string& targetUrl,
    const std::string& apiKey
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "INSERT INTO backend_registration "
        "(user_id, service_name, target_url, api_key) "
        "VALUES ($1, $2, $3, $4) "
        "RETURNING " + BACKEND_COLUMNS,
        userId,
        serviceName,
        targetUrl,
        apiKey
    );

    transaction.commit();

    return rowToBackend(result[0]);
}

std::vector<webhawk::models::BackendRegistration>
BackendRepository::findAllByUserId(
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT " + BACKEND_COLUMNS + " "
        "FROM backend_registration "
        "WHERE user_id = $1 "
        "ORDER BY created_at DESC",
        userId
    );

    transaction.commit();

    std::vector<webhawk::models::BackendRegistration> backends;
    backends.reserve(result.size());

    for (const auto& row : result)
    {
        backends.push_back(rowToBackend(row));
    }

    return backends;
}

std::optional<webhawk::models::BackendRegistration>
BackendRepository::findByIdAndUserId(
    int backendId,
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT " + BACKEND_COLUMNS + " "
        "FROM backend_registration "
        "WHERE id = $1 AND user_id = $2",
        backendId,
        userId
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToBackend(result[0]);
}

std::optional<webhawk::models::BackendRegistration>
BackendRepository::findActiveByApiKey(
    const std::string& apiKey
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT " + BACKEND_COLUMNS + " "
        "FROM backend_registration "
        "WHERE api_key = $1 AND is_active = TRUE",
        apiKey
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToBackend(result[0]);
}

std::optional<webhawk::models::BackendRegistration>
BackendRepository::updateBackend(
    int backendId,
    int userId,
    const std::string& serviceName,
    const std::string& targetUrl,
    bool isActive
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "UPDATE backend_registration "
        "SET service_name = $1, "
        "target_url = $2, "
        "is_active = $3, "
        "updated_at = NOW() "
        "WHERE id = $4 AND user_id = $5 "
        "RETURNING " + BACKEND_COLUMNS,
        serviceName,
        targetUrl,
        isActive,
        backendId,
        userId
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToBackend(result[0]);
}

std::optional<webhawk::models::BackendRegistration>
BackendRepository::disableBackend(
    int backendId,
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "UPDATE backend_registration "
        "SET is_active = FALSE, updated_at = NOW() "
        "WHERE id = $1 AND user_id = $2 "
        "RETURNING " + BACKEND_COLUMNS,
        backendId,
        userId
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToBackend(result[0]);
}