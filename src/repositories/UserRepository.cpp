#include "repositories/UserRepository.h"

#include "database/Database.h"

using namespace webhawk::repositories;

int UserRepository::countUsers()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM users"
    );
}