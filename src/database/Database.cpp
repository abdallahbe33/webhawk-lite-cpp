#include "database/Database.h"

#include "config/AppConfig.h"

#include <pqxx/pqxx>

using namespace webhawk::database;

bool Database::canConnect()
{
    pqxx::connection connection(
        webhawk::config::AppConfig::databaseConnectionString()
    );

    return connection.is_open();
}

int Database::countQuery(
    const std::string& sql
)
{
    pqxx::connection connection(
        webhawk::config::AppConfig::databaseConnectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result = transaction.exec(sql);

    transaction.commit();

    if (result.empty())
    {
        return 0;
    }

    return result[0][0].as<int>();
}

std::string Database::connectionString()
{
    return webhawk::config::AppConfig::databaseConnectionString();
}