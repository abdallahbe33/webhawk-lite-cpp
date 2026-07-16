#pragma once

#include "models/User.h"

#include <optional>
#include <string>

namespace webhawk::repositories
{
class UserRepository
{
public:
    static int countUsers();

    static std::optional<webhawk::models::User> findByEmail(
        const std::string& email
    );

    static webhawk::models::User createUser(
        const std::string& name,
        const std::string& email,
        const std::string& passwordHash
    );
};
}