#include "repositories/AnalyticsRepository.h"

#include "database/Database.h"

#include <pqxx/pqxx>

using namespace webhawk::repositories;

webhawk::models::AnalyticsSummary
AnalyticsRepository::summaryForUser(
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result =
        transaction.exec_params(
            "SELECT "
            "COUNT(*)::BIGINT "
            "AS total_scanned, "

            "COUNT(*) FILTER "
            "(WHERE sl.is_blocked)::BIGINT "
            "AS total_blocked, "

            "COUNT(*) FILTER "
            "(WHERE NOT sl.is_blocked)::BIGINT "
            "AS total_allowed "

            "FROM security_logs sl "
            "JOIN backend_registration br "
            "ON br.id = sl.backend_id "
            "WHERE br.user_id = $1",

            userId
        );

    transaction.commit();

    webhawk::models::AnalyticsSummary summary;

    summary.totalScanned =
        result[0]["total_scanned"]
            .as<long long>();

    summary.totalBlocked =
        result[0]["total_blocked"]
            .as<long long>();

    summary.totalAllowed =
        result[0]["total_allowed"]
            .as<long long>();

    summary.blockRate =
        summary.totalScanned == 0
            ? 0.0
            : (
                static_cast<double>(
                    summary.totalBlocked
                ) * 100.0
            ) / static_cast<double>(
                summary.totalScanned
            );

    return summary;
}

std::vector<
    webhawk::models::AttackTypeCount
>
AnalyticsRepository::attacksByTypeForUser(
    int userId
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result =
        transaction.exec_params(
            "SELECT sl.attack_type, "
            "COUNT(*)::BIGINT AS attack_count "

            "FROM security_logs sl "
            "JOIN backend_registration br "
            "ON br.id = sl.backend_id "

            "WHERE br.user_id = $1 "
            "AND sl.is_blocked = TRUE "
            "AND sl.attack_type IS NOT NULL "
            "AND sl.attack_type <> 'NONE' "

            "GROUP BY sl.attack_type "
            "ORDER BY attack_count DESC, "
            "sl.attack_type",

            userId
        );

    transaction.commit();

    std::vector<
        webhawk::models::AttackTypeCount
    > attacks;

    for (const auto& row : result)
    {
        attacks.push_back({
            row["attack_type"]
                .as<std::string>(),

            row["attack_count"]
                .as<long long>()
        });
    }

    return attacks;
}

std::vector<
    webhawk::models::AttackTimelinePoint
>
AnalyticsRepository::attacksOverTimeForUser(
    int userId,
    int days
)
{
    pqxx::connection connection(
        webhawk::database::Database::
            connectionString()
    );

    pqxx::work transaction(connection);

    pqxx::result result =
        transaction.exec_params(
            "WITH date_series AS ("

            "SELECT generate_series("
            "CURRENT_DATE - "
            "($2::INTEGER - 1), "
            "CURRENT_DATE, "
            "INTERVAL '1 day'"
            ")::DATE AS day"
            "), "

            "daily AS ("
            "SELECT "
            "sl.created_at::DATE AS day, "
            "COUNT(*)::BIGINT "
            "AS total_requests, "

            "COUNT(*) FILTER "
            "(WHERE sl.is_blocked)::BIGINT "
            "AS blocked_requests "

            "FROM security_logs sl "
            "JOIN backend_registration br "
            "ON br.id = sl.backend_id "

            "WHERE br.user_id = $1 "
            "AND sl.created_at >= "
            "CURRENT_DATE - "
            "($2::INTEGER - 1) "

            "GROUP BY sl.created_at::DATE"
            ") "

            "SELECT "
            "TO_CHAR(ds.day, 'YYYY-MM-DD') "
            "AS date, "

            "COALESCE("
            "d.total_requests, 0"
            ")::BIGINT AS total_requests, "

            "COALESCE("
            "d.blocked_requests, 0"
            ")::BIGINT AS blocked_requests "

            "FROM date_series ds "
            "LEFT JOIN daily d "
            "ON d.day = ds.day "
            "ORDER BY ds.day",

            userId,
            days
        );

    transaction.commit();

    std::vector<
        webhawk::models::AttackTimelinePoint
    > timeline;

    for (const auto& row : result)
    {
        timeline.push_back({
            row["date"].as<std::string>(),

            row["total_requests"]
                .as<long long>(),

            row["blocked_requests"]
                .as<long long>()
        });
    }

    return timeline;
}