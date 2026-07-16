#include "repositories/SecurityLogRepository.h"

#include "database/Database.h"

using namespace webhawk::repositories;

int SecurityLogRepository::countSecurityLogs()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM security_logs"
    );
}