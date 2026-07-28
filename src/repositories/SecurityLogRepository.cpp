#include "repositories/SecurityLogRepository.h"

#include "database/Database.h"

#include <json/json.h>
#include <pqxx/pqxx>

using namespace webhawk::repositories;

namespace
{
template <typename RowType>
webhawk::models::SecurityLog rowToSecurityLog(
    const RowType& row
)
{
    webhawk::models::SecurityLog log;

    log.id =
        row["id"].template as<int>();

    log.backendId =
        row["backend_id"].template as<int>();

    log.ipAddress =
        row["ip_address"]
            .template as<std::string>();

    log.method =
        row["method"]
            .template as<std::string>();

    log.endpoint =
        row["endpoint"]
            .template as<std::string>();

    log.attackType =
        row["attack_type"].is_null()
            ? "NONE"
            : row["attack_type"]
                .template as<std::string>();

    log.isBlocked =
        row["is_blocked"]
            .template as<bool>();

    log.requestData =
        row["request_data"].is_null()
            ? "{}"
            : row["request_data"]
                .template as<std::string>();

    log.createdAt =
        row["created_at"]
            .template as<std::string>();

    return log;
}

const std::string LOG_COLUMNS =
    "sl.id, sl.backend_id, sl.ip_address, "
    "sl.method, sl.endpoint, sl.attack_type, "
    "sl.is_blocked, "
    "sl.request_data::text AS request_data, "
    "sl.created_at";

std::string compactJson(
    const Json::Value& value
)
{
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    return Json::writeString(
        builder,
        value
    );
}
}

int SecurityLogRepository::countSecurityLogs()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM security_logs"
    );
}

webhawk::models::SecurityLog
SecurityLogRepository::createLog(
    int backendId,
    const std::string& ipAddress,
    const std::string& method,
    const std::string& endpoint,
    const std::string& attackType,
    bool isBlocked,
    const Json::Value& requestData
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result =
        transaction.exec_params(
            "INSERT INTO security_logs "
            "(backend_id, ip_address, method, "
            "endpoint, attack_type, is_blocked, "
            "request_data) "
            "VALUES "
            "($1, $2, $3, $4, $5, $6, "
            "$7::jsonb) "
            "RETURNING "
            "id, backend_id, ip_address, method, "
            "endpoint, attack_type, is_blocked, "
            "request_data::text AS request_data, "
            "created_at",

            backendId,
            ipAddress,
            method,
            endpoint,
            attackType,
            isBlocked,
            compactJson(requestData)
        );

    transaction.commit();

    return rowToSecurityLog(
        result[0]
    );
}

std::vector<webhawk::models::SecurityLog>
SecurityLogRepository::findByUserId(
    int userId,
    const SecurityLogQuery& query
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    const int offset =
        (query.page - 1) * query.pageSize;

    pqxx::result result =
        transaction.exec_params(
            "SELECT " + LOG_COLUMNS + " "
            "FROM security_logs sl "
            "JOIN backend_registration br "
            "ON br.id = sl.backend_id "
            "WHERE br.user_id = $1 "
            "AND ($2 = '' "
            "OR sl.attack_type = $2) "
            "AND ($3 = -1 "
            "OR sl.is_blocked = ($3 = 1)) "
            "AND ($4 = 0 "
            "OR sl.backend_id = $4) "
            "ORDER BY sl.created_at DESC "
            "LIMIT $5 OFFSET $6",

            userId,
            query.attackType,
            query.blockedFilter,
            query.backendId,
            query.pageSize,
            offset
        );

    transaction.commit();

    std::vector<
        webhawk::models::SecurityLog
    > logs;

    logs.reserve(result.size());

    for (const auto& row : result)
    {
        logs.push_back(
            rowToSecurityLog(row)
        );
    }

    return logs;
}

long long SecurityLogRepository::countByUserId(
    int userId,
    const SecurityLogQuery& query
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result =
        transaction.exec_params(
            "SELECT COUNT(*)::BIGINT AS total "
            "FROM security_logs sl "
            "JOIN backend_registration br "
            "ON br.id = sl.backend_id "
            "WHERE br.user_id = $1 "
            "AND ($2 = '' "
            "OR sl.attack_type = $2) "
            "AND ($3 = -1 "
            "OR sl.is_blocked = ($3 = 1)) "
            "AND ($4 = 0 "
            "OR sl.backend_id = $4)",

            userId,
            query.attackType,
            query.blockedFilter,
            query.backendId
        );

    transaction.commit();

    return result[0]["total"]
        .as<long long>();
}