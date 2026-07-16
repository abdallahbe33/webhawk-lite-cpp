#include "repositories/SessionRepository.h"

#include "database/Database.h"

using namespace webhawk::repositories;

int SessionRepository::countSessions()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM user_sessions"
    );
}