#include "repositories/RateLimitRepository.h"

#include "database/Database.h"

#include <pqxx/pqxx>

using namespace webhawk::repositories;

namespace
{
template <typename RowType>
webhawk::models::RateLimit rowToRateLimit(
    const RowType& row
)
{
    webhawk::models::RateLimit rateLimit;

    rateLimit.id =
        row["id"].template as<int>();

    rateLimit.backendId =
        row["backend_id"].template as<int>();

    rateLimit.ipAddress =
        row["ip_address"].template as<std::string>();

    rateLimit.endpoint =
        row["endpoint"].template as<std::string>();

    rateLimit.requestCount =
        row["request_count"].template as<int>();

    rateLimit.windowStart =
        row["window_start"].template as<std::string>();

    rateLimit.blockedUntil =
        row["blocked_until"].is_null()
            ? ""
            : row["blocked_until"]
                .template as<std::string>();

    rateLimit.isBlocked =
        row["is_blocked"].template as<bool>();

    rateLimit.remainingRequests =
        row["remaining_requests"].template as<int>();

    rateLimit.retryAfterSeconds =
        row["retry_after_seconds"].template as<int>();

    return rateLimit;
}
}

int RateLimitRepository::countRateLimitRecords()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM rate_limit"
    );
}

webhawk::models::RateLimit
RateLimitRepository::consumeRequest(
    int backendId,
    const std::string& ipAddress,
    const std::string& endpoint,
    int requestLimit,
    int windowSeconds,
    int blockSeconds
)
{
    pqxx::connection connection(
        webhawk::database::Database::connectionString()
    );

    pqxx::work transaction(connection);

    const std::string activeBlock =
        "rate_limit.is_blocked = TRUE "
        "AND rate_limit.blocked_until > NOW()";

    const std::string resetRequired =
        "rate_limit.window_start "
        "+ ($5 * INTERVAL '1 second') <= NOW() "
        "OR (rate_limit.is_blocked = TRUE "
        "AND rate_limit.blocked_until <= NOW())";

    pqxx::result result = transaction.exec_params(
        "INSERT INTO rate_limit "
        "(backend_id, ip_address, endpoint, "
        "request_count, window_start, blocked_until, "
        "is_blocked) "
        "VALUES ($1, $2, $3, 1, NOW(), NULL, FALSE) "

        "ON CONFLICT "
        "(backend_id, ip_address, endpoint) "
        "DO UPDATE SET "

        "request_count = CASE "
        "WHEN " + activeBlock + " "
        "THEN rate_limit.request_count "
        "WHEN " + resetRequired + " "
        "THEN 1 "
        "ELSE rate_limit.request_count + 1 "
        "END, "

        "window_start = CASE "
        "WHEN " + resetRequired + " "
        "THEN NOW() "
        "ELSE rate_limit.window_start "
        "END, "

        "blocked_until = CASE "
        "WHEN " + activeBlock + " "
        "THEN rate_limit.blocked_until "
        "WHEN " + resetRequired + " "
        "THEN NULL "
        "WHEN rate_limit.request_count + 1 > $4 "
        "THEN NOW() + ($6 * INTERVAL '1 second') "
        "ELSE NULL "
        "END, "

        "is_blocked = CASE "
        "WHEN " + activeBlock + " "
        "THEN TRUE "
        "WHEN " + resetRequired + " "
        "THEN FALSE "
        "WHEN rate_limit.request_count + 1 > $4 "
        "THEN TRUE "
        "ELSE FALSE "
        "END "

        "RETURNING "
        "id, backend_id, ip_address, endpoint, "
        "request_count, window_start, blocked_until, "
        "is_blocked, "

        "GREATEST($4 - request_count, 0)::INTEGER "
        "AS remaining_requests, "

        "CASE "
        "WHEN is_blocked "
        "AND blocked_until IS NOT NULL "
        "THEN CEIL(GREATEST(EXTRACT(EPOCH FROM "
        "(blocked_until - NOW())), 0))::INTEGER "
        "ELSE 0 "
        "END AS retry_after_seconds",

        backendId,
        ipAddress,
        endpoint,
        requestLimit,
        windowSeconds,
        blockSeconds
    );

    transaction.commit();

    return rowToRateLimit(result[0]);
}