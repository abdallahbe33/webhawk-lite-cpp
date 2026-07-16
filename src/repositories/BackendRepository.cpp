#include "repositories/BackendRepository.h"

#include "database/Database.h"

using namespace webhawk::repositories;

int BackendRepository::countBackends()
{
    return webhawk::database::Database::countQuery(
        "SELECT COUNT(*) FROM backend_registration"
    );
}