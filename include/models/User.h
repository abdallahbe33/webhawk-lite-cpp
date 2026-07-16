#pragma once

#include <string>

namespace webhawk::models
{
struct User
{
    int id{};
    std::string name;
    std::string email;
    std::string passwordHash;
    std::string createdAt;
    std::string updatedAt;
};
}