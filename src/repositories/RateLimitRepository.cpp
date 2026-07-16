#include "repositories/RateLimitRepository.h"

#include "database/Database.h"

using namespace webhawk::repositories;

int RateLimitRepository::countRateLimitRecords()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM rate_limit"
    );
}