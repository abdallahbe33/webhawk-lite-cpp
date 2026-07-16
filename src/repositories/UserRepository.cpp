#include "repositories/UserRepository.h"

#include "database/Database.h"

#include <pqxx/pqxx>

using namespace webhawk::repositories;

namespace
{
template <typename RowType>
webhawk::models::User rowToUser(
    const RowType& row
)
{
    webhawk::models::User user;

    user.id = row["id"].template as<int>();
    user.name = row["name"].template as<std::string>();
    user.email = row["email"].template as<std::string>();
    user.passwordHash = row["password_hash"].template as<std::string>();
    user.createdAt = row["created_at"].template as<std::string>();
    user.updatedAt = row["updated_at"].template as<std::string>();

    return user;
}
}

int UserRepository::countUsers()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM users"
    );
}

std::optional<webhawk::models::User> UserRepository::findByEmail(
    const std::string& email
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "SELECT id, name, email, password_hash, created_at, updated_at "
        "FROM users "
        "WHERE email = $1",
        email
    );

    transaction.commit();

    if (result.empty())
    {
        return std::nullopt;
    }

    return rowToUser(result[0]);
}

webhawk::models::User UserRepository::createUser(
    const std::string& name,
    const std::string& email,
    const std::string& passwordHash
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec_params(
        "INSERT INTO users (name, email, password_hash) "
        "VALUES ($1, $2, $3) "
        "RETURNING id, name, email, password_hash, created_at, updated_at",
        name,
        email,
        passwordHash
    );

    transaction.commit();

    return rowToUser(result[0]);
}